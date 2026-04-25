/*
 * bench_sym_hash.c
 *
 * Pure C latency/throughput benchmark for QAT SHA-256 hash.
 * A session is initialized once; the same pre-allocated USDM buffers are
 * reused across every timed iteration.  Digest output goes to a dedicated
 * USDM buffer pointed to by pDigestResult.
 *
 * Compile:
 *   gcc -O2 -o bench_sym_hash bench_sym_hash.c \
 *       -I/usr/include/qat -lqat -lusdm -lpthread
 *
 * Run:
 *   sudo ./bench_sym_hash
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
#include "cpa_cy_sym.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"

#define DATA_BYTES      4096
#define SHA256_DIGEST   32
#define WARMUP_ITERS    200
#define LAT_ITERS       5000
#define THRU_ITERS      10000
#define THRU_THREADS    16

#define QAT_MAX_INSTANCES 64
static CpaInstanceHandle   g_cyInst[QAT_MAX_INSTANCES];
static CpaCySymSessionCtx  g_session[QAT_MAX_INSTANCES];
static Cpa16U              g_numInst     = 0;
static volatile Cpa32U     g_instRR      = 0;
static pthread_t           g_pollThread;
static volatile int        g_keepPolling = 0;

typedef struct {
    volatile int complete;
    CpaStatus    status;
} Completion;

typedef struct { long long *ns; } ThruArg;

static void symCallback(void *tag, CpaStatus status,
                        const CpaCySymOp opType, void *pOpData,
                        CpaBufferList *pDst, CpaBoolean verified)
{
    Completion *c = (Completion *)tag;
    if (c) { c->status = status; c->complete = 1; }
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
    for (Cpa16U i = 0; i < g_numInst; i++) {
        if (g_session[i]) {
            cpaCySymRemoveSession(g_cyInst[i], g_session[i]);
            free(g_session[i]);
            g_session[i] = NULL;
        }
        cpaCyStopInstance(g_cyInst[i]);
    }
    icp_sal_userStop();
}

static long long nowNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int doHash(CpaCySymOpData *opData,
                  CpaBufferList *src, CpaBufferList *dst)
{
    Cpa32U idx = __atomic_fetch_add(&g_instRR, 1, __ATOMIC_RELAXED) % g_numInst;
    opData->sessionCtx = g_session[idx];
    Completion comp = { .complete = 0, .status = CPA_STATUS_SUCCESS };
    CpaStatus s = cpaCySymPerformOp(g_cyInst[idx], &comp, opData, src, dst, NULL);
    if (s != CPA_STATUS_SUCCESS) return -1;
    while (!comp.complete) usleep(1);
    return (comp.status == CPA_STATUS_SUCCESS) ? 0 : -1;
}

static void *hashThruWorker(void *arg)
{
    ThruArg *a = (ThruArg *)arg;

    Cpa32U metaSize = 0;
    cpaCyBufferListGetMetaSize(g_cyInst[0], 1, &metaSize);

    Cpa8U *uData    = qaeMemAllocNUMA(DATA_BYTES,    0, 64);
    Cpa8U *uDigest  = qaeMemAllocNUMA(SHA256_DIGEST, 0, 64);
    Cpa8U *uSrcMeta = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;
    Cpa8U *uDstMeta = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;

    for (int i = 0; i < DATA_BYTES; i++) uData[i] = (Cpa8U)(i & 0xFF);

    CpaFlatBuffer dataFlat = { .dataLenInBytes = DATA_BYTES, .pData = uData };
    CpaBufferList srcList  = { .numBuffers = 1, .pBuffers = &dataFlat,
                               .pPrivateMetaData = uSrcMeta };
    CpaBufferList dstList  = { .numBuffers = 1, .pBuffers = &dataFlat,
                               .pPrivateMetaData = uDstMeta };

    CpaCySymOpData opData;
    memset(&opData, 0, sizeof(opData));
    opData.packetType               = CPA_CY_SYM_PACKET_TYPE_FULL;
    opData.hashStartSrcOffsetInBytes = 0;
    opData.messageLenToHashInBytes  = DATA_BYTES;
    opData.pDigestResult            = uDigest;

    for (int i = 0; i < THRU_ITERS; i++) {
        long long t0 = nowNs();
        doHash(&opData, &srcList, &dstList);
        a->ns[i] = nowNs() - t0;
    }

    qaeMemFreeNUMA((void **)&uData);
    qaeMemFreeNUMA((void **)&uDigest);
    if (uSrcMeta) qaeMemFreeNUMA((void **)&uSrcMeta);
    if (uDstMeta) qaeMemFreeNUMA((void **)&uDstMeta);
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
    printf("=== bench_sym_hash: QAT SHA-256 (%d bytes, pure C) ===\n\n",
           DATA_BYTES);

    if (initQat() != 0) return 1;

    /* Allocate and initialize SHA-256 session. */
    Cpa32U sessionSize = 0;
    CpaCySymSessionSetupData ssd;
    memset(&ssd, 0, sizeof(ssd));
    ssd.sessionPriority                        = CPA_CY_PRIORITY_NORMAL;
    ssd.symOperation                           = CPA_CY_SYM_OP_HASH;
    ssd.hashSetupData.hashAlgorithm            = CPA_CY_SYM_HASH_SHA256;
    ssd.hashSetupData.hashMode                 = CPA_CY_SYM_HASH_MODE_PLAIN;
    ssd.hashSetupData.digestResultLenInBytes   = SHA256_DIGEST;
    ssd.digestIsAppended                       = CPA_FALSE;
    ssd.verifyDigest                           = CPA_FALSE;
    ssd.partialsNotRequired                    = CPA_TRUE;

    for (Cpa16U i = 0; i < g_numInst; i++) {
        cpaCySymSessionCtxGetSize(g_cyInst[i], &ssd, &sessionSize);
        g_session[i] = malloc(sessionSize);
        if (!g_session[i]) { fprintf(stderr, "session malloc failed\n"); goto cleanup; }
        if (cpaCySymInitSession(g_cyInst[i], symCallback, &ssd, g_session[i])
                != CPA_STATUS_SUCCESS) {
            fprintf(stderr, "cpaCySymInitSession failed\n");
            goto cleanup;
        }
    }

    Cpa32U metaSize = 0;
    cpaCyBufferListGetMetaSize(g_cyInst[0], 1, &metaSize);

    Cpa8U *uData      = qaeMemAllocNUMA(DATA_BYTES, 0, 64);
    Cpa8U *uDigest    = qaeMemAllocNUMA(SHA256_DIGEST, 0, 64);
    Cpa8U *uSrcMeta   = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;
    Cpa8U *uDstMeta   = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;

    for (int i = 0; i < DATA_BYTES; i++) uData[i] = (Cpa8U)(i & 0xFF);

    CpaFlatBuffer dataFlat = { .dataLenInBytes = DATA_BYTES, .pData = uData };

    CpaBufferList srcList = {
        .numBuffers       = 1,
        .pBuffers         = &dataFlat,
        .pPrivateMetaData = uSrcMeta
    };
    /* Hash-only: dst is in-place (same underlying data). */
    CpaBufferList dstList = {
        .numBuffers       = 1,
        .pBuffers         = &dataFlat,
        .pPrivateMetaData = uDstMeta
    };

    CpaCySymOpData opData;
    memset(&opData, 0, sizeof(opData));
    opData.sessionCtx               = g_session[0]; /* overwritten per-call by doHash */
    opData.packetType               = CPA_CY_SYM_PACKET_TYPE_FULL;
    opData.hashStartSrcOffsetInBytes = 0;
    opData.messageLenToHashInBytes  = DATA_BYTES;
    opData.pDigestResult            = uDigest;

    printf("Warming up (%d iters)...\n", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        if (doHash(&opData, &srcList, &dstList) != 0) {
            fprintf(stderr, "Warmup failed at iter %d\n", i);
            goto cleanup_bufs;
        }
    }

    printf("Latency benchmark (%d iters)...\n", LAT_ITERS);
    long long *latNs = malloc(LAT_ITERS * sizeof(long long));

    long long wallStart = nowNs();
    for (int i = 0; i < LAT_ITERS; i++) {
        long long t0 = nowNs();
        doHash(&opData, &srcList, &dstList);
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
        pthread_create(&thruTh[t], NULL, hashThruWorker, &thruA[t]);
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

cleanup_bufs:
    qaeMemFreeNUMA((void **)&uData);
    qaeMemFreeNUMA((void **)&uDigest);
    if (uSrcMeta) qaeMemFreeNUMA((void **)&uSrcMeta);
    if (uDstMeta) qaeMemFreeNUMA((void **)&uDstMeta);
cleanup:
    teardownQat();
    printf("\nDone.\n");
    return 0;
}
