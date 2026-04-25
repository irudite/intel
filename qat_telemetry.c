/*
 * qat_telemetry.c
 *
 * Multi-threaded QAT RSA benchmark with telemetry.
 *
 * Per-operation telemetry:
 *   - Latency histogram (min, max, mean, p50, p95, p99)
 *   - Submit/complete counts, errors
 *   - Throughput (ops/sec)
 *
 * Hardware telemetry (queried from QAT driver):
 *   - RSA encrypt/decrypt request counts
 *   - Request completions and errors
 *   - Periodic snapshots every 1 second during run
 *
 * Multi-threaded with configurable in-flight depth.
 * All worker threads share a single QAT instance (single endpoint).
 *
 * Compile:
 *   gcc -O2 -o qat_telemetry qat_telemetry.c -I/usr/include/qat -lqat -lusdm -lpthread -lm
 *
 * Run:
 *   sudo ./qat_telemetry [threads] [in_flight] [duration_sec]
 *   sudo ./qat_telemetry 4 16 10
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <math.h>

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_im.h"
#include "cpa_cy_rsa.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"

/* ================================================================
 * Configuration
 * ================================================================ */
#define KEY_SIZE_BYTES       256    /* RSA-2048 */
#define MAX_THREADS          16
#define MAX_IN_FLIGHT        64     /* per thread */
#define DEFAULT_THREADS      4
#define DEFAULT_IN_FLIGHT    8
#define DEFAULT_DURATION     10     /* seconds */
#define HIST_BUCKETS         100000 /* for percentile calc */

/* ================================================================
 * Globals
 * ================================================================ */
static CpaInstanceHandle g_inst = NULL;
static pthread_t g_pollThread;
static pthread_t g_telemetryThread;
static volatile int g_keepRunning = 0;
static volatile int g_keepPolling = 0;

/* Global counters (atomic) */
static atomic_ullong g_totalSubmitted = 0;
static atomic_ullong g_totalCompleted = 0;
static atomic_ullong g_totalErrors    = 0;
static atomic_ullong g_inFlight       = 0;

/* Latency histogram - stores raw latencies, sorted at the end */
static atomic_ullong *g_latencies = NULL;
static atomic_ullong g_latencyIdx = 0;
static size_t g_latencyCap = 0;

/* Test vectors */
static Cpa8U testModN[KEY_SIZE_BYTES];
static Cpa8U testExpE[KEY_SIZE_BYTES];
static Cpa8U testPlaintext[KEY_SIZE_BYTES];

/* ================================================================
 * Per-request context
 *
 * Each in-flight request carries its own submit timestamp and
 * pointers to its USDM buffers. The callback uses this to
 * compute latency and mark the slot free.
 * ================================================================ */
typedef struct {
    long long submitTimeNs;
    volatile int inUse;
    volatile CpaStatus status;

    /* Pooled USDM buffers (allocated once per slot) */
    Cpa8U *uN;
    Cpa8U *uE;
    Cpa8U *uPt;
    Cpa8U *uCt;

    CpaCyRsaPublicKey pubKey;
    CpaCyRsaEncryptOpData opData;
    CpaFlatBuffer outBuf;
} RequestSlot;

/* Each worker thread has its own pool of request slots */
typedef struct {
    int threadId;
    int inFlightDepth;
    RequestSlot *slots;

    /* Per-thread stats */
    unsigned long long localSubmitted;
    unsigned long long localCompleted;
    unsigned long long localErrors;
} WorkerCtx;

/* ================================================================
 * Utilities
 * ================================================================ */
static long long nowNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void initTestVectors(void)
{
    memset(testModN, 0xFF, KEY_SIZE_BYTES);
    testModN[0] = 0xC0;
    testModN[KEY_SIZE_BYTES - 1] = 0x01;

    memset(testExpE, 0, KEY_SIZE_BYTES);
    testExpE[KEY_SIZE_BYTES - 3] = 0x01;
    testExpE[KEY_SIZE_BYTES - 1] = 0x01;

    memset(testPlaintext, 0, KEY_SIZE_BYTES);
    testPlaintext[KEY_SIZE_BYTES - 1] = 0x42;
}

/* ================================================================
 * Polling thread
 * ================================================================ */
static void *pollLoop(void *arg)
{
    (void)arg;
    while (g_keepPolling) {
        icp_sal_CyPollInstance(g_inst, 0);
    }
    return NULL;
}

/* ================================================================
 * RSA callback
 *
 * Called by the polling thread when a request completes.
 * We record the latency, update counters, and mark the slot free.
 * ================================================================ */
static void rsaCallback(void *tag, CpaStatus status,
                        void *pOpData, CpaFlatBuffer *pOut)
{
    RequestSlot *slot = (RequestSlot *)tag;
    long long completeTime = nowNs();
    long long latency = completeTime - slot->submitTimeNs;

    /* Record latency sample */
    unsigned long long idx = atomic_fetch_add(&g_latencyIdx, 1);
    if (idx < g_latencyCap) {
        atomic_store(&g_latencies[idx], latency);
    }

    if (status == CPA_STATUS_SUCCESS) {
        atomic_fetch_add(&g_totalCompleted, 1);
    } else {
        atomic_fetch_add(&g_totalErrors, 1);
    }
    atomic_fetch_sub(&g_inFlight, 1);

    slot->status = status;
    slot->inUse = 0;
}

/* ================================================================
 * Allocate and prime a request slot
 * ================================================================ */
static int initSlot(RequestSlot *slot)
{
    slot->uN  = qaeMemAllocNUMA(KEY_SIZE_BYTES, 0, 64);
    slot->uE  = qaeMemAllocNUMA(KEY_SIZE_BYTES, 0, 64);
    slot->uPt = qaeMemAllocNUMA(KEY_SIZE_BYTES, 0, 64);
    slot->uCt = qaeMemAllocNUMA(KEY_SIZE_BYTES, 0, 64);

    if (!slot->uN || !slot->uE || !slot->uPt || !slot->uCt) {
        return -1;
    }

    memcpy(slot->uN,  testModN,      KEY_SIZE_BYTES);
    memcpy(slot->uE,  testExpE,      KEY_SIZE_BYTES);
    memcpy(slot->uPt, testPlaintext, KEY_SIZE_BYTES);

    memset(&slot->pubKey, 0, sizeof(slot->pubKey));
    slot->pubKey.modulusN.dataLenInBytes = KEY_SIZE_BYTES;
    slot->pubKey.modulusN.pData = slot->uN;
    slot->pubKey.publicExponentE.dataLenInBytes = KEY_SIZE_BYTES;
    slot->pubKey.publicExponentE.pData = slot->uE;

    memset(&slot->opData, 0, sizeof(slot->opData));
    slot->opData.pPublicKey = &slot->pubKey;
    slot->opData.inputData.dataLenInBytes = KEY_SIZE_BYTES;
    slot->opData.inputData.pData = slot->uPt;

    slot->outBuf.dataLenInBytes = KEY_SIZE_BYTES;
    slot->outBuf.pData = slot->uCt;

    slot->inUse = 0;
    return 0;
}

static void freeSlot(RequestSlot *slot)
{
    if (slot->uN)  qaeMemFreeNUMA((void **)&slot->uN);
    if (slot->uE)  qaeMemFreeNUMA((void **)&slot->uE);
    if (slot->uPt) qaeMemFreeNUMA((void **)&slot->uPt);
    if (slot->uCt) qaeMemFreeNUMA((void **)&slot->uCt);
}

/* ================================================================
 * Worker thread
 *
 * Submits RSA encrypt requests as fast as slots are available.
 * Each thread maintains its own pool of in-flight slots.
 * ================================================================ */
static void *workerThread(void *arg)
{
    WorkerCtx *ctx = (WorkerCtx *)arg;

    while (g_keepRunning) {
        /* Find a free slot */
        for (int i = 0; i < ctx->inFlightDepth; i++) {
            if (!g_keepRunning) break;

            RequestSlot *slot = &ctx->slots[i];
            if (slot->inUse) continue;

            slot->inUse = 1;
            slot->submitTimeNs = nowNs();

            atomic_fetch_add(&g_inFlight, 1);
            atomic_fetch_add(&g_totalSubmitted, 1);
            ctx->localSubmitted++;

            CpaStatus s = cpaCyRsaEncrypt(
                g_inst,
                rsaCallback,
                (void *)slot,
                &slot->opData,
                &slot->outBuf);

            if (s != CPA_STATUS_SUCCESS) {
                /* Submission failed (retry or hardware full).
                 * Mark slot free and try again. */
                slot->inUse = 0;
                atomic_fetch_sub(&g_inFlight, 1);
                atomic_fetch_sub(&g_totalSubmitted, 1);
                ctx->localSubmitted--;
                /* Back off briefly to let queue drain */
                usleep(1);
            }
        }
    }

    /* Drain: wait for all outstanding slots to complete */
    int anyInUse;
    do {
        anyInUse = 0;
        for (int i = 0; i < ctx->inFlightDepth; i++) {
            if (ctx->slots[i].inUse) { anyInUse = 1; break; }
        }
        if (anyInUse) usleep(100);
    } while (anyInUse);

    return NULL;
}

/* ================================================================
 * Hardware telemetry snapshot
 *
 * Queries QAT driver for RSA-specific stats on this instance.
 * ================================================================ */
static void printHwStats(const char *label)
{
    CpaCyRsaStats64 stats;
    memset(&stats, 0, sizeof(stats));

    CpaStatus s = cpaCyRsaQueryStats64(g_inst, &stats);
    if (s != CPA_STATUS_SUCCESS) {
        printf("[hw] %s  (stats query failed: %d)\n", label, s);
        return;
    }

    printf("[hw] %s  enc_req=%llu  enc_done=%llu  enc_err=%llu  "
           "dec_req=%llu  dec_done=%llu  dec_err=%llu\n",
           label,
           (unsigned long long)stats.numRsaEncryptRequests,
           (unsigned long long)stats.numRsaEncryptCompleted,
           (unsigned long long)stats.numRsaEncryptRequestErrors,
           (unsigned long long)stats.numRsaDecryptRequests,
           (unsigned long long)stats.numRsaDecryptCompleted,
           (unsigned long long)stats.numRsaDecryptRequestErrors);
}

/* ================================================================
 * Telemetry thread
 *
 * Prints per-second snapshots of software and hardware counters
 * while the benchmark runs.
 * ================================================================ */
static void *telemetryLoop(void *arg)
{
    (void)arg;
    long long startNs = nowNs();
    unsigned long long lastCompleted = 0;

    while (g_keepRunning) {
        sleep(1);
        if (!g_keepRunning) break;

        long long elapsedNs = nowNs() - startNs;
        double elapsedSec = elapsedNs / 1e9;

        unsigned long long submitted = atomic_load(&g_totalSubmitted);
        unsigned long long completed = atomic_load(&g_totalCompleted);
        unsigned long long errors    = atomic_load(&g_totalErrors);
        unsigned long long inFlight  = atomic_load(&g_inFlight);

        unsigned long long deltaCompleted = completed - lastCompleted;
        lastCompleted = completed;

        printf("[sw] t=%5.1fs  submitted=%-8llu  completed=%-8llu  "
               "in_flight=%-3llu  errors=%-3llu  ops/sec=%llu\n",
               elapsedSec, submitted, completed, inFlight, errors,
               deltaCompleted);

        char label[32];
        snprintf(label, sizeof(label), "t=%5.1fs", elapsedSec);
        printHwStats(label);
    }

    return NULL;
}

/* ================================================================
 * Latency stats computation
 * ================================================================ */
static int cmpU64(const void *a, const void *b)
{
    unsigned long long x = *(const unsigned long long *)a;
    unsigned long long y = *(const unsigned long long *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

static void printLatencyStats(void)
{
    unsigned long long count = atomic_load(&g_latencyIdx);
    if (count > g_latencyCap) count = g_latencyCap;
    if (count == 0) {
        printf("No latency samples recorded.\n");
        return;
    }

    /* Copy samples into a sortable array */
    unsigned long long *samples = malloc(count * sizeof(unsigned long long));
    for (unsigned long long i = 0; i < count; i++) {
        samples[i] = atomic_load(&g_latencies[i]);
    }

    qsort(samples, count, sizeof(unsigned long long), cmpU64);

    unsigned long long min = samples[0];
    unsigned long long max = samples[count - 1];
    unsigned long long p50 = samples[count * 50 / 100];
    unsigned long long p95 = samples[count * 95 / 100];
    unsigned long long p99 = samples[count * 99 / 100];

    /* Mean */
    double sum = 0;
    for (unsigned long long i = 0; i < count; i++) {
        sum += samples[i];
    }
    double mean = sum / count;

    /* Stddev */
    double sqSum = 0;
    for (unsigned long long i = 0; i < count; i++) {
        double d = samples[i] - mean;
        sqSum += d * d;
    }
    double stddev = sqrt(sqSum / count);

    printf("  samples:  %llu\n", count);
    printf("  min:      %8.1f us\n", min / 1000.0);
    printf("  mean:     %8.1f us\n", mean / 1000.0);
    printf("  p50:      %8.1f us\n", p50 / 1000.0);
    printf("  p95:      %8.1f us\n", p95 / 1000.0);
    printf("  p99:      %8.1f us\n", p99 / 1000.0);
    printf("  max:      %8.1f us\n", max / 1000.0);
    printf("  stddev:   %8.1f us\n", stddev / 1000.0);

    free(samples);
}

/* ================================================================
 * QAT init/shutdown
 * ================================================================ */
static int initQat(void)
{
    if (icp_sal_userStartMultiProcess("SSL", CPA_FALSE) != CPA_STATUS_SUCCESS) {
        fprintf(stderr, "SAL start failed\n");
        return -1;
    }

    Cpa16U num = 0;
    cpaCyGetNumInstances(&num);
    if (num == 0) {
        fprintf(stderr, "No instances\n");
        icp_sal_userStop();
        return -1;
    }

    CpaInstanceHandle *insts = malloc(num * sizeof(CpaInstanceHandle));
    cpaCyGetInstances(num, insts);
    g_inst = insts[0];
    free(insts);

    cpaCySetAddressTranslation(g_inst, qaeVirtToPhysNUMA);
    cpaCyStartInstance(g_inst);

    g_keepPolling = 1;
    pthread_create(&g_pollThread, NULL, pollLoop, NULL);

    return 0;
}

static void shutdownQat(void)
{
    g_keepPolling = 0;
    pthread_join(g_pollThread, NULL);
    cpaCyStopInstance(g_inst);
    icp_sal_userStop();
}

/* ================================================================
 * Main
 * ================================================================ */
int main(int argc, char *argv[])
{
    int numThreads = DEFAULT_THREADS;
    int inFlightDepth = DEFAULT_IN_FLIGHT;
    int duration = DEFAULT_DURATION;

    if (argc >= 2) numThreads = atoi(argv[1]);
    if (argc >= 3) inFlightDepth = atoi(argv[2]);
    if (argc >= 4) duration = atoi(argv[3]);

    if (numThreads > MAX_THREADS) numThreads = MAX_THREADS;
    if (inFlightDepth > MAX_IN_FLIGHT) inFlightDepth = MAX_IN_FLIGHT;
    if (numThreads < 1) numThreads = 1;
    if (inFlightDepth < 1) inFlightDepth = 1;
    if (duration < 1) duration = 1;

    printf("=== QAT RSA-2048 Telemetry Benchmark ===\n");
    printf("Threads:        %d\n", numThreads);
    printf("In-flight/thrd: %d\n", inFlightDepth);
    printf("Total in-flight:%d\n", numThreads * inFlightDepth);
    printf("Duration:       %d sec\n\n", duration);

    initTestVectors();

    if (initQat() != 0) return 1;

    /* Show instance info */
    CpaInstanceInfo2 info = {0};
    cpaCyInstanceGetInfo2(g_inst, &info);
    printf("Instance:       %s\n", info.instName);
    printf("Node:           %d\n", info.nodeAffinity);
    printf("Polled:         %s\n", info.isPolled ? "yes" : "no");
    printf("State:          %s\n\n",
           info.operState == CPA_OPER_STATE_UP ? "UP" : "DOWN");

    /* Initial hardware snapshot */
    printHwStats("t=  0.0s (baseline)");
    printf("\n");

    /* Allocate latency histogram (rough upper bound on expected ops) */
    g_latencyCap = (size_t)numThreads * 100000;
    if (g_latencyCap > HIST_BUCKETS * numThreads) {
        g_latencyCap = HIST_BUCKETS * numThreads;
    }
    g_latencies = malloc(g_latencyCap * sizeof(atomic_ullong));
    for (size_t i = 0; i < g_latencyCap; i++) {
        atomic_store(&g_latencies[i], 0);
    }

    /* Set up worker contexts */
    WorkerCtx workers[MAX_THREADS];
    pthread_t threads[MAX_THREADS];

    for (int t = 0; t < numThreads; t++) {
        workers[t].threadId = t;
        workers[t].inFlightDepth = inFlightDepth;
        workers[t].slots = calloc(inFlightDepth, sizeof(RequestSlot));
        workers[t].localSubmitted = 0;
        workers[t].localCompleted = 0;
        workers[t].localErrors = 0;

        for (int i = 0; i < inFlightDepth; i++) {
            if (initSlot(&workers[t].slots[i]) != 0) {
                fprintf(stderr, "Slot init failed for thread %d slot %d\n", t, i);
                return 1;
            }
        }
    }

    /* Start telemetry and workers */
    g_keepRunning = 1;
    long long runStart = nowNs();

    pthread_create(&g_telemetryThread, NULL, telemetryLoop, NULL);

    for (int t = 0; t < numThreads; t++) {
        pthread_create(&threads[t], NULL, workerThread, &workers[t]);
    }

    /* Let it run */
    sleep(duration);

    /* Stop everyone */
    g_keepRunning = 0;

    for (int t = 0; t < numThreads; t++) {
        pthread_join(threads[t], NULL);
    }
    pthread_join(g_telemetryThread, NULL);

    long long runEnd = nowNs();
    double runSec = (runEnd - runStart) / 1e9;

    /* Final results */
    printf("\n=== Final Results ===\n");
    unsigned long long submitted = atomic_load(&g_totalSubmitted);
    unsigned long long completed = atomic_load(&g_totalCompleted);
    unsigned long long errors    = atomic_load(&g_totalErrors);

    printf("Runtime:       %.2f sec\n", runSec);
    printf("Submitted:     %llu\n", submitted);
    printf("Completed:     %llu\n", completed);
    printf("Errors:        %llu\n", errors);
    printf("Throughput:    %.0f ops/sec\n", completed / runSec);
    printf("Per-thread:    %.0f ops/sec\n",
           (completed / runSec) / numThreads);

    printf("\n=== Latency Distribution ===\n");
    printLatencyStats();

    printf("\n=== Final Hardware Stats ===\n");
    printHwStats("final");

    /* Cleanup */
    for (int t = 0; t < numThreads; t++) {
        for (int i = 0; i < inFlightDepth; i++) {
            freeSlot(&workers[t].slots[i]);
        }
        free(workers[t].slots);
    }
    free((void *)g_latencies);

    shutdownQat();
    printf("\nDone.\n");
    return 0;
}
