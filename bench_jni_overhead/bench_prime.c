/*
 * bench_prime.c
 *
 * Pure C latency/throughput benchmark for QAT primality testing.
 * Tests a known 512-bit prime candidate using GCD + Fermat + 5 Miller-Rabin
 * rounds.  USDM buffers are pre-allocated once.
 *
 * Compile:
 *   gcc -O2 -o bench_prime bench_prime.c \
 *       -I/usr/include/qat -lqat -lusdm -lpthread
 *
 * Run:
 *   sudo ./bench_prime
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_im.h"
#include "cpa_cy_prime.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"

#define PRIME_BYTES  64         /* 512-bit prime candidate */
#define MR_ROUNDS    5
#define WARMUP_ITERS 200
#define LAT_ITERS    5000
#define THRU_ITERS   10000
#define THRU_THREADS 16

#define QAT_MAX_INSTANCES 64
static CpaInstanceHandle   g_cyInst[QAT_MAX_INSTANCES];
static Cpa16U              g_numInst     = 0;
static volatile Cpa32U     g_instRR      = 0;
static pthread_t           g_pollThread;
static volatile int        g_keepPolling = 0;

static CpaInstanceHandle pickInstance(void)
{
    Cpa32U idx = __atomic_fetch_add(&g_instRR, 1, __ATOMIC_RELAXED) % g_numInst;
    return g_cyInst[idx];
}

typedef struct {
    volatile int  complete;
    CpaStatus     status;
    CpaBoolean    passed;
} PrimeCompletion;

typedef struct { long long *ns; } ThruArg;

/*
 * RFC 2409 Group 1 prime (512-bit, big-endian).
 * This is a well-known prime, so all primality tests should pass.
 */
static const Cpa8U g_prime512[PRIME_BYTES] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
    0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
    0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
    0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
    0xF2,0x5F,0x14,0x37
};

static void primeCallback(void *tag, CpaStatus status,
                          void *pOpData, CpaBoolean testPassed)
{
    PrimeCompletion *c = (PrimeCompletion *)tag;
    if (c) {
        c->status  = status;
        c->passed  = testPassed;
        c->complete = 1;
    }
}

static void *pollLoop(void *arg)
{
    (void)arg;
    while (g_keepPolling) {
        for (Cpa16U i = 0; i < g_numInst; i++)
            icp_sal_CyPollInstance(g_cyInst[i], 0);
        usleep(10);
    }
    return NULL;
}

static int initQat(void)
{
    CpaStatus s;
    Cpa16U num = 0;

    s = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (s != CPA_STATUS_SUCCESS) {
        fprintf(stderr, "SAL start failed: %d\n", s);
        return -1;
    }

    cpaCyGetNumInstances(&num);
    if (num == 0) {
        fprintf(stderr, "No CY instances\n");
        icp_sal_userStop();
        return -1;
    }

    if (num > QAT_MAX_INSTANCES) num = QAT_MAX_INSTANCES;
    CpaInstanceHandle *insts = malloc(num * sizeof(CpaInstanceHandle));
    cpaCyGetInstances(num, insts);
    g_numInst = num;
    memcpy(g_cyInst, insts, num * sizeof(CpaInstanceHandle));
    free(insts);

    for (Cpa16U i = 0; i < g_numInst; i++) {
        cpaCySetAddressTranslation(g_cyInst[i], qaeVirtToPhysNUMA);
        cpaCyStartInstance(g_cyInst[i]);
    }

    g_keepPolling = 1;
    pthread_create(&g_pollThread, NULL, pollLoop, NULL);
    return 0;
}

static void teardownQat(void)
{
    g_keepPolling = 0;
    pthread_join(g_pollThread, NULL);
    for (Cpa16U i = 0; i < g_numInst; i++)
        cpaCyStopInstance(g_cyInst[i]);
    icp_sal_userStop();
}

static long long nowNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int doPrimeTest(CpaCyPrimeTestOpData *op)
{
    PrimeCompletion comp = { .complete = 0, .status = CPA_STATUS_SUCCESS,
                             .passed = CPA_FALSE };
    CpaBoolean passed = CPA_FALSE;
    CpaStatus s = cpaCyPrimeTest(pickInstance(), primeCallback, &comp, op, &passed);
    if (s != CPA_STATUS_SUCCESS) return -1;
    while (!comp.complete) usleep(1);
    return (comp.status == CPA_STATUS_SUCCESS) ? 0 : -1;
}

static void *primeThruWorker(void *arg)
{
    ThruArg *a = (ThruArg *)arg;

    Cpa32U mrBufLen    = MR_ROUNDS * PRIME_BYTES;
    Cpa8U *uCandidate  = qaeMemAllocNUMA(PRIME_BYTES, 0, 64);
    Cpa8U *uMrInput    = qaeMemAllocNUMA(mrBufLen,    0, 64);

    memcpy(uCandidate, g_prime512, PRIME_BYTES);

    for (Cpa32U r = 0; r < MR_ROUNDS; r++) {
        memset(&uMrInput[r * PRIME_BYTES], 0, PRIME_BYTES);
        uMrInput[r * PRIME_BYTES + PRIME_BYTES - 1] = (Cpa8U)(2 + r);
    }

    CpaCyPrimeTestOpData op;
    memset(&op, 0, sizeof(op));
    op.primeCandidate.dataLenInBytes         = PRIME_BYTES;
    op.primeCandidate.pData                  = uCandidate;
    op.performGcdTest                        = CPA_TRUE;
    op.performFermatTest                     = CPA_TRUE;
    op.numMillerRabinRounds                  = MR_ROUNDS;
    op.millerRabinRandomInput.dataLenInBytes = mrBufLen;
    op.millerRabinRandomInput.pData          = uMrInput;

    for (int i = 0; i < THRU_ITERS; i++) {
        long long t0 = nowNs();
        doPrimeTest(&op);
        a->ns[i] = nowNs() - t0;
    }

    qaeMemFreeNUMA((void **)&uCandidate);
    qaeMemFreeNUMA((void **)&uMrInput);
    return NULL;
}

static int cmpLong(const void *a, const void *b)
{
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}

static void printStats(const char *label, long long *ns, int n, double elapsedSec)
{
    qsort(ns, n, sizeof(long long), cmpLong);

    long long sum = 0;
    for (int i = 0; i < n; i++) sum += ns[i];

    double mean  = (double)sum / n / 1000.0;
    double min   = ns[0]                / 1000.0;
    double p50   = ns[n * 50 / 100]    / 1000.0;
    double p95   = ns[n * 95 / 100]    / 1000.0;
    double p99   = ns[n * 99 / 100]    / 1000.0;
    double p999  = ns[n * 999 / 1000]  / 1000.0;
    double max   = ns[n - 1]           / 1000.0;
    double ops   = n / elapsedSec;

    printf("\n--- %s ---\n", label);
    printf("  iterations  : %d\n",     n);
    printf("  elapsed     : %.3f s\n", elapsedSec);
    printf("  throughput  : %.0f ops/sec\n", ops);
    printf("  latency (us): mean=%.1f  min=%.1f  p50=%.1f  p95=%.1f  p99=%.1f  p99.9=%.1f  max=%.1f\n",
           mean, min, p50, p95, p99, p999, max);
}

int main(void)
{
    printf("=== bench_prime: QAT %d-bit primality test (GCD+Fermat+%dxMR, pure C) ===\n\n",
           PRIME_BYTES * 8, MR_ROUNDS);

    if (initQat() != 0) return 1;

    /*
     * Miller-Rabin random inputs: MR_ROUNDS witnesses, each PRIME_BYTES long.
     * Each witness must be in (1, p-1).  Use fixed synthetic values here.
     */
    Cpa32U mrBufLen = MR_ROUNDS * PRIME_BYTES;
    Cpa8U *uCandidate = qaeMemAllocNUMA(PRIME_BYTES, 0, 64);
    Cpa8U *uMrInput   = qaeMemAllocNUMA(mrBufLen, 0, 64);
    Cpa8U *uPrimeBuf  = qaeMemAllocNUMA(PRIME_BYTES, 0, 64);

    memcpy(uCandidate, g_prime512, PRIME_BYTES);
    memcpy(uPrimeBuf,  g_prime512, PRIME_BYTES);

    /* Fill MR witnesses: each is a different small offset from 2. */
    for (Cpa32U r = 0; r < MR_ROUNDS; r++) {
        memset(&uMrInput[r * PRIME_BYTES], 0, PRIME_BYTES);
        uMrInput[r * PRIME_BYTES + PRIME_BYTES - 1] = (Cpa8U)(2 + r);
    }

    CpaCyPrimeTestOpData op;
    memset(&op, 0, sizeof(op));
    op.primeCandidate.dataLenInBytes    = PRIME_BYTES;
    op.primeCandidate.pData             = uCandidate;
    op.performGcdTest                   = CPA_TRUE;
    op.performFermatTest                = CPA_TRUE;
    op.numMillerRabinRounds             = MR_ROUNDS;
    op.millerRabinRandomInput.dataLenInBytes = mrBufLen;
    op.millerRabinRandomInput.pData          = uMrInput;

    printf("Warming up (%d iters)...\n", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        if (doPrimeTest(&op) != 0) {
            fprintf(stderr, "Warmup failed at iter %d\n", i);
            goto cleanup;
        }
    }

    printf("Latency benchmark (%d iters)...\n", LAT_ITERS);
    long long *latNs = malloc(LAT_ITERS * sizeof(long long));

    long long wallStart = nowNs();
    for (int i = 0; i < LAT_ITERS; i++) {
        long long t0 = nowNs();
        doPrimeTest(&op);
        latNs[i] = nowNs() - t0;
    }
    long long wallEnd = nowNs();

    printStats("Latency", latNs, LAT_ITERS,
               (double)(wallEnd - wallStart) / 1e9);
    free(latNs);

    printf("\nThroughput benchmark (%d threads x %d iters)...\n",
           THRU_THREADS, THRU_ITERS);
    pthread_t  thruTh[THRU_THREADS];
    ThruArg    thruA[THRU_THREADS];
    long long *thruBufs[THRU_THREADS];
    for (int t = 0; t < THRU_THREADS; t++) {
        thruBufs[t] = malloc(THRU_ITERS * sizeof(long long));
        thruA[t].ns = thruBufs[t];
    }
    long long thruStart = nowNs();
    for (int t = 0; t < THRU_THREADS; t++)
        pthread_create(&thruTh[t], NULL, primeThruWorker, &thruA[t]);
    for (int t = 0; t < THRU_THREADS; t++)
        pthread_join(thruTh[t], NULL);
    long long thruEnd = nowNs();

    int totalThru = THRU_THREADS * THRU_ITERS;
    long long *thruNs = malloc(totalThru * sizeof(long long));
    for (int t = 0; t < THRU_THREADS; t++) {
        memcpy(&thruNs[t * THRU_ITERS], thruBufs[t], THRU_ITERS * sizeof(long long));
        free(thruBufs[t]);
    }
    printStats("Throughput (multi-threaded)", thruNs, totalThru,
               (double)(thruEnd - thruStart) / 1e9);
    free(thruNs);

cleanup:
    qaeMemFreeNUMA((void **)&uCandidate);
    qaeMemFreeNUMA((void **)&uMrInput);
    qaeMemFreeNUMA((void **)&uPrimeBuf);
    teardownQat();
    printf("\nDone.\n");
    return 0;
}
