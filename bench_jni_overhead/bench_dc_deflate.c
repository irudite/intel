/*
 * bench_dc_deflate.c
 *
 * Pure C latency/throughput benchmark for QAT Deflate compress and
 * decompress (stateless, static Huffman).
 *
 * Uses the DC instance family (separate from CY).  Both compress and
 * decompress are benchmarked back-to-back using the same 4 KB data block.
 *
 * Compile:
 *   gcc -O2 -o bench_dc_deflate bench_dc_deflate.c \
 *       -I/usr/include/qat -lqat -lusdm -lpthread
 *
 * Run:
 *   sudo ./bench_dc_deflate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_dc.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"

#define SRC_BYTES    4096
#define DST_BYTES    (SRC_BYTES * 2)    /* worst-case compressed output */
#define WARMUP_ITERS 200
#define LAT_ITERS    5000
#define THRU_ITERS   10000
#define THRU_THREADS 16

#define QAT_MAX_INSTANCES 64
static CpaInstanceHandle   g_dcInst[QAT_MAX_INSTANCES];
static CpaDcSessionHandle  g_session[QAT_MAX_INSTANCES];
static Cpa16U              g_numInst     = 0;
static volatile Cpa32U     g_instRR      = 0;
static pthread_t           g_pollThread;
static volatile int        g_keepPolling = 0;

static Cpa16U pickInstIdx(void)
{
    return (Cpa16U)(__atomic_fetch_add(&g_instRR, 1, __ATOMIC_RELAXED) % g_numInst);
}

typedef struct {
    volatile int complete;
    CpaStatus    status;
} Completion;

typedef struct {
    long long *ns;
    Cpa8U     *compData;   /* pre-compressed input (for decompress workers) */
    Cpa32U     compLen;
} DcThruArg;

static void dcCallback(void *tag, CpaStatus status)
{
    Completion *c = (Completion *)tag;
    if (c) { c->status = status; c->complete = 1; }
}

static void *pollLoop(void *arg)
{
    (void)arg;
    while (g_keepPolling) {
        for (Cpa16U i = 0; i < g_numInst; i++)
            icp_sal_DcPollInstance(g_dcInst[i], 0);
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

    cpaDcGetNumInstances(&num);
    if (num == 0) {
        fprintf(stderr, "No DC instances\n");
        icp_sal_userStop();
        return -1;
    }

    if (num > QAT_MAX_INSTANCES) num = QAT_MAX_INSTANCES;
    CpaInstanceHandle *insts = malloc(num * sizeof(CpaInstanceHandle));
    cpaDcGetInstances(num, insts);
    g_numInst = num;
    memcpy(g_dcInst, insts, num * sizeof(CpaInstanceHandle));
    free(insts);

    CpaDcSessionSetupData ssd;
    memset(&ssd, 0, sizeof(ssd));
    ssd.compLevel       = CPA_DC_L1;
    ssd.compType        = CPA_DC_DEFLATE;
    ssd.huffType        = CPA_DC_HT_STATIC;
    ssd.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
    ssd.sessDirection   = CPA_DC_DIR_COMBINED;
    ssd.sessState       = CPA_DC_STATELESS;
    ssd.windowSize      = CPA_DC_WINSIZE_32K;
    ssd.checksum        = CPA_DC_CRC32;

    for (Cpa16U i = 0; i < g_numInst; i++) {
        cpaDcSetAddressTranslation(g_dcInst[i], qaeVirtToPhysNUMA);

        s = cpaDcStartInstance(g_dcInst[i], 0, NULL);
        if (s != CPA_STATUS_SUCCESS) {
            fprintf(stderr, "cpaDcStartInstance failed: %d\n", s);
            icp_sal_userStop();
            return -1;
        }

        Cpa32U sessSize = 0;
        cpaDcGetSessionSize(g_dcInst[i], &ssd, &sessSize, NULL);

        g_session[i] = qaeMemAllocNUMA(sessSize, 0, 64);
        if (!g_session[i]) {
            fprintf(stderr, "session alloc failed\n");
            cpaDcStopInstance(g_dcInst[i]);
            icp_sal_userStop();
            return -1;
        }

        s = cpaDcInitSession(g_dcInst[i], g_session[i], &ssd, NULL, dcCallback);
        if (s != CPA_STATUS_SUCCESS) {
            fprintf(stderr, "cpaDcInitSession failed: %d\n", s);
            qaeMemFreeNUMA((void **)&g_session[i]);
            cpaDcStopInstance(g_dcInst[i]);
            icp_sal_userStop();
            return -1;
        }
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
            cpaDcRemoveSession(g_dcInst[i], g_session[i]);
            qaeMemFreeNUMA((void **)&g_session[i]);
        }
        cpaDcStopInstance(g_dcInst[i]);
    }
    icp_sal_userStop();
}

static long long nowNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int doCompress(CpaBufferList *src, CpaBufferList *dst,
                      CpaDcRqResults *results)
{
    Cpa16U idx = pickInstIdx();
    Completion comp = { .complete = 0, .status = CPA_STATUS_SUCCESS };
    CpaStatus s = cpaDcCompressData(g_dcInst[idx], g_session[idx], src, dst,
                                    results, CPA_DC_FLUSH_FINAL, &comp);
    if (s != CPA_STATUS_SUCCESS) return -1;
    while (!comp.complete) usleep(1);
    return (comp.status == CPA_STATUS_SUCCESS) ? 0 : -1;
}

static int doDecompress(CpaBufferList *src, CpaBufferList *dst,
                        CpaDcRqResults *results)
{
    Cpa16U idx = pickInstIdx();
    Completion comp = { .complete = 0, .status = CPA_STATUS_SUCCESS };
    CpaStatus s = cpaDcDecompressData(g_dcInst[idx], g_session[idx], src, dst,
                                      results, CPA_DC_FLUSH_FINAL, &comp);
    if (s != CPA_STATUS_SUCCESS) return -1;
    while (!comp.complete) usleep(1);
    return (comp.status == CPA_STATUS_SUCCESS) ? 0 : -1;
}

static void *compThruWorker(void *arg)
{
    DcThruArg *a = (DcThruArg *)arg;

    Cpa32U metaSize = 0;
    cpaDcBufferListGetMetaSize(g_dcInst[0], 1, &metaSize);

    Cpa8U *uSrc      = qaeMemAllocNUMA(SRC_BYTES, 0, 64);
    Cpa8U *uComp     = qaeMemAllocNUMA(DST_BYTES, 0, 64);
    Cpa8U *uSrcMeta  = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;
    Cpa8U *uCompMeta = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;

    for (int i = 0; i < SRC_BYTES; i++) uSrc[i] = (Cpa8U)(i % 16);

    CpaFlatBuffer srcFlat  = { .dataLenInBytes = SRC_BYTES, .pData = uSrc  };
    CpaFlatBuffer compFlat = { .dataLenInBytes = DST_BYTES, .pData = uComp };
    CpaBufferList srcList  = { .numBuffers = 1, .pBuffers = &srcFlat,
                               .pPrivateMetaData = uSrcMeta  };
    CpaBufferList compList = { .numBuffers = 1, .pBuffers = &compFlat,
                               .pPrivateMetaData = uCompMeta };
    CpaDcRqResults results;

    for (int i = 0; i < THRU_ITERS; i++) {
        compFlat.dataLenInBytes = DST_BYTES;
        memset(&results, 0, sizeof(results));
        long long t0 = nowNs();
        doCompress(&srcList, &compList, &results);
        a->ns[i] = nowNs() - t0;
    }

    qaeMemFreeNUMA((void **)&uSrc);
    qaeMemFreeNUMA((void **)&uComp);
    if (uSrcMeta)  qaeMemFreeNUMA((void **)&uSrcMeta);
    if (uCompMeta) qaeMemFreeNUMA((void **)&uCompMeta);
    return NULL;
}

static void *decompThruWorker(void *arg)
{
    DcThruArg *a = (DcThruArg *)arg;

    Cpa32U metaSize = 0;
    cpaDcBufferListGetMetaSize(g_dcInst[0], 1, &metaSize);

    Cpa8U *uComp     = qaeMemAllocNUMA(a->compLen, 0, 64);
    Cpa8U *uDecomp   = qaeMemAllocNUMA(SRC_BYTES,  0, 64);
    Cpa8U *uCompMeta = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;
    Cpa8U *uDcmpMeta = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;

    memcpy(uComp, a->compData, a->compLen);

    CpaFlatBuffer compFlat = { .dataLenInBytes = a->compLen, .pData = uComp   };
    CpaFlatBuffer dcmpFlat = { .dataLenInBytes = SRC_BYTES,  .pData = uDecomp };
    CpaBufferList compList = { .numBuffers = 1, .pBuffers = &compFlat,
                               .pPrivateMetaData = uCompMeta };
    CpaBufferList dcmpList = { .numBuffers = 1, .pBuffers = &dcmpFlat,
                               .pPrivateMetaData = uDcmpMeta };
    CpaDcRqResults results;

    for (int i = 0; i < THRU_ITERS; i++) {
        dcmpFlat.dataLenInBytes = SRC_BYTES;
        memset(&results, 0, sizeof(results));
        long long t0 = nowNs();
        doDecompress(&compList, &dcmpList, &results);
        a->ns[i] = nowNs() - t0;
    }

    qaeMemFreeNUMA((void **)&uComp);
    qaeMemFreeNUMA((void **)&uDecomp);
    if (uCompMeta) qaeMemFreeNUMA((void **)&uCompMeta);
    if (uDcmpMeta) qaeMemFreeNUMA((void **)&uDcmpMeta);
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
    printf("=== bench_dc_deflate: QAT Deflate compress + decompress (%d bytes, pure C) ===\n\n",
           SRC_BYTES);

    if (initQat() != 0) return 1;

    Cpa32U metaSize = 0;
    cpaDcBufferListGetMetaSize(g_dcInst[0], 1, &metaSize);

    /* Plain-text source and compressed output buffers. */
    Cpa8U *uSrc       = qaeMemAllocNUMA(SRC_BYTES, 0, 64);
    Cpa8U *uComp      = qaeMemAllocNUMA(DST_BYTES, 0, 64);
    Cpa8U *uDecomp    = qaeMemAllocNUMA(SRC_BYTES, 0, 64);
    Cpa8U *uSrcMeta   = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;
    Cpa8U *uCompMeta  = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;
    Cpa8U *uDcmpMeta  = metaSize ? qaeMemAllocNUMA(metaSize, 0, 64) : NULL;

    /* Fill source with a compressible repeating pattern. */
    for (int i = 0; i < SRC_BYTES; i++) uSrc[i] = (Cpa8U)(i % 16);

    /* Compress once to produce a valid compressed stream for decompress bench. */
    CpaFlatBuffer srcFlat  = { .dataLenInBytes = SRC_BYTES,  .pData = uSrc   };
    CpaFlatBuffer compFlat = { .dataLenInBytes = DST_BYTES,  .pData = uComp  };
    CpaFlatBuffer dcmpFlat = { .dataLenInBytes = SRC_BYTES,  .pData = uDecomp };

    CpaBufferList srcList = {
        .numBuffers = 1, .pBuffers = &srcFlat, .pPrivateMetaData = uSrcMeta
    };
    CpaBufferList compList = {
        .numBuffers = 1, .pBuffers = &compFlat, .pPrivateMetaData = uCompMeta
    };
    CpaBufferList dcmpList = {
        .numBuffers = 1, .pBuffers = &dcmpFlat, .pPrivateMetaData = uDcmpMeta
    };

    CpaDcRqResults results;
    memset(&results, 0, sizeof(results));

    /* Produce a compressed buffer once (for decompress benchmarking). */
    if (doCompress(&srcList, &compList, &results) != 0) {
        fprintf(stderr, "Initial compress failed\n");
        goto cleanup;
    }
    Cpa32U compressedLen = results.produced;
    printf("Initial compress: %u -> %u bytes (ratio %.2f)\n\n",
           SRC_BYTES, compressedLen, (double)SRC_BYTES / compressedLen);

    /* ----------------------------------------------------------------
     * Compress benchmark
     * ---------------------------------------------------------------- */
    printf("Warming up compress (%d iters)...\n", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        compFlat.dataLenInBytes = DST_BYTES;    /* reset output capacity */
        memset(&results, 0, sizeof(results));
        if (doCompress(&srcList, &compList, &results) != 0) {
            fprintf(stderr, "Compress warmup failed at iter %d\n", i);
            goto cleanup;
        }
    }

    printf("Compress latency benchmark (%d iters)...\n", LAT_ITERS);
    long long *latNs = malloc(LAT_ITERS * sizeof(long long));
    long long wallStart = nowNs();
    for (int i = 0; i < LAT_ITERS; i++) {
        compFlat.dataLenInBytes = DST_BYTES;
        memset(&results, 0, sizeof(results));
        long long t0 = nowNs();
        doCompress(&srcList, &compList, &results);
        latNs[i] = nowNs() - t0;
    }
    long long wallEnd = nowNs();
    printStats("Compress Latency", latNs, LAT_ITERS,
               (double)(wallEnd - wallStart) / 1e9);
    free(latNs);

    printf("\nCompress throughput benchmark (%d threads x %d iters)...\n",
           THRU_THREADS, THRU_ITERS);
    {
        pthread_t   thruTh[THRU_THREADS];
        DcThruArg   thruA[THRU_THREADS];
        long long  *thruBufs[THRU_THREADS];
        for (int t = 0; t < THRU_THREADS; t++) {
            thruBufs[t] = malloc(THRU_ITERS * sizeof(long long));
            thruA[t].ns = thruBufs[t];
        }
        long long thruStart = nowNs();
        for (int t = 0; t < THRU_THREADS; t++)
            pthread_create(&thruTh[t], NULL, compThruWorker, &thruA[t]);
        for (int t = 0; t < THRU_THREADS; t++)
            pthread_join(thruTh[t], NULL);
        long long thruEnd = nowNs();

        int totalThru = THRU_THREADS * THRU_ITERS;
        long long *thruNs = malloc(totalThru * sizeof(long long));
        for (int t = 0; t < THRU_THREADS; t++) {
            memcpy(&thruNs[t * THRU_ITERS], thruBufs[t], THRU_ITERS * sizeof(long long));
            free(thruBufs[t]);
        }
        printStats("Compress Throughput (multi-threaded)", thruNs, totalThru,
                   (double)(thruEnd - thruStart) / 1e9);
        free(thruNs);
    }

    /* ----------------------------------------------------------------
     * Decompress benchmark — input is the compressed stream produced above.
     * ---------------------------------------------------------------- */
    compFlat.dataLenInBytes = compressedLen;

    printf("\nWarming up decompress (%d iters)...\n", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        dcmpFlat.dataLenInBytes = SRC_BYTES;
        memset(&results, 0, sizeof(results));
        if (doDecompress(&compList, &dcmpList, &results) != 0) {
            fprintf(stderr, "Decompress warmup failed at iter %d\n", i);
            goto cleanup;
        }
    }

    printf("Decompress latency benchmark (%d iters)...\n", LAT_ITERS);
    latNs = malloc(LAT_ITERS * sizeof(long long));
    wallStart = nowNs();
    for (int i = 0; i < LAT_ITERS; i++) {
        dcmpFlat.dataLenInBytes = SRC_BYTES;
        memset(&results, 0, sizeof(results));
        long long t0 = nowNs();
        doDecompress(&compList, &dcmpList, &results);
        latNs[i] = nowNs() - t0;
    }
    wallEnd = nowNs();
    printStats("Decompress Latency", latNs, LAT_ITERS,
               (double)(wallEnd - wallStart) / 1e9);
    free(latNs);

    printf("\nDecompress throughput benchmark (%d threads x %d iters)...\n",
           THRU_THREADS, THRU_ITERS);
    {
        pthread_t   thruTh[THRU_THREADS];
        DcThruArg   thruA[THRU_THREADS];
        long long  *thruBufs[THRU_THREADS];
        for (int t = 0; t < THRU_THREADS; t++) {
            thruBufs[t]        = malloc(THRU_ITERS * sizeof(long long));
            thruA[t].ns        = thruBufs[t];
            thruA[t].compData  = uComp;
            thruA[t].compLen   = compressedLen;
        }
        long long thruStart = nowNs();
        for (int t = 0; t < THRU_THREADS; t++)
            pthread_create(&thruTh[t], NULL, decompThruWorker, &thruA[t]);
        for (int t = 0; t < THRU_THREADS; t++)
            pthread_join(thruTh[t], NULL);
        long long thruEnd = nowNs();

        int totalThru = THRU_THREADS * THRU_ITERS;
        long long *thruNs = malloc(totalThru * sizeof(long long));
        for (int t = 0; t < THRU_THREADS; t++) {
            memcpy(&thruNs[t * THRU_ITERS], thruBufs[t], THRU_ITERS * sizeof(long long));
            free(thruBufs[t]);
        }
        printStats("Decompress Throughput (multi-threaded)", thruNs, totalThru,
                   (double)(thruEnd - thruStart) / 1e9);
        free(thruNs);
    }

cleanup:
    qaeMemFreeNUMA((void **)&uSrc);
    qaeMemFreeNUMA((void **)&uComp);
    qaeMemFreeNUMA((void **)&uDecomp);
    if (uSrcMeta)  qaeMemFreeNUMA((void **)&uSrcMeta);
    if (uCompMeta) qaeMemFreeNUMA((void **)&uCompMeta);
    if (uDcmpMeta) qaeMemFreeNUMA((void **)&uDcmpMeta);
    teardownQat();
    printf("\nDone.\n");
    return 0;
}
