/*
 * bench_rsa_decrypt.c
 *
 * Pure C latency/throughput benchmark for QAT RSA-2048 decrypt (private-key
 * operation using Type-1 representation: N and D).
 *
 * USDM buffers are pre-allocated once.  The private key is synthetic — this
 * measures hardware dispatch latency, not cryptographic correctness.
 *
 * Compile:
 *   gcc -O2 -o bench_rsa_decrypt bench_rsa_decrypt.c \
 *       -I/usr/include/qat -lqat -lusdm -lpthread
 *
 * Run:
 *   sudo ./bench_rsa_decrypt
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
#include "cpa_cy_rsa.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"

#define KEY_BYTES    256        /* RSA-2048 */
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
    volatile int complete;
    CpaStatus    status;
} Completion;

typedef struct { long long *ns; } ThruArg;

static Cpa8U g_modN[KEY_BYTES];
static Cpa8U g_privD[KEY_BYTES];
static Cpa8U g_ciphertext[KEY_BYTES];

static void initTestVectors(void)
{
    /* Synthetic 2048-bit modulus: top two bits set, bottom bit set (odd). */
    memset(g_modN, 0xFF, KEY_BYTES);
    g_modN[0] = 0xC0;
    g_modN[KEY_BYTES - 1] = 0x01;

    /* Synthetic private exponent D — just needs to be < N for the hardware. */
    memset(g_privD, 0xAA, KEY_BYTES);
    g_privD[0] = 0x80;
    g_privD[KEY_BYTES - 1] = 0x03;

    /* Ciphertext is a small value (ensures ct < N). */
    memset(g_ciphertext, 0, KEY_BYTES);
    g_ciphertext[KEY_BYTES - 1] = 0x42;
    g_ciphertext[KEY_BYTES - 2] = 0x41;
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

static void rsaDecryptCallback(void *tag, CpaStatus status,
                               void *pOpData, CpaFlatBuffer *pOut)
{
    Completion *c = (Completion *)tag;
    if (c) { c->status = status; c->complete = 1; }
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

static int doDecrypt(CpaCyRsaDecryptOpData *op, CpaFlatBuffer *out)
{
    Completion comp = { .complete = 0, .status = CPA_STATUS_SUCCESS };
    CpaStatus s = cpaCyRsaDecrypt(pickInstance(), rsaDecryptCallback, &comp, op, out);
    if (s != CPA_STATUS_SUCCESS) return -1;
    while (!comp.complete) usleep(1);
    return (comp.status == CPA_STATUS_SUCCESS) ? 0 : -1;
}

static void *rsaDecThruWorker(void *arg)
{
    ThruArg *a = (ThruArg *)arg;

    Cpa8U *uN  = qaeMemAllocNUMA(KEY_BYTES, 0, 64);
    Cpa8U *uD  = qaeMemAllocNUMA(KEY_BYTES, 0, 64);
    Cpa8U *uCt = qaeMemAllocNUMA(KEY_BYTES, 0, 64);
    Cpa8U *uPt = qaeMemAllocNUMA(KEY_BYTES, 0, 64);

    memcpy(uN,  g_modN,       KEY_BYTES);
    memcpy(uD,  g_privD,      KEY_BYTES);
    memcpy(uCt, g_ciphertext, KEY_BYTES);

    CpaCyRsaPrivateKeyRep1 keyRep1;
    memset(&keyRep1, 0, sizeof(keyRep1));
    keyRep1.modulusN.dataLenInBytes         = KEY_BYTES;
    keyRep1.modulusN.pData                  = uN;
    keyRep1.privateExponentD.dataLenInBytes = KEY_BYTES;
    keyRep1.privateExponentD.pData          = uD;

    CpaCyRsaPrivateKey privKey;
    memset(&privKey, 0, sizeof(privKey));
    privKey.version           = CPA_CY_RSA_VERSION_TWO_PRIME;
    privKey.privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1;
    privKey.privateKeyRep1    = keyRep1;

    CpaCyRsaDecryptOpData op;
    memset(&op, 0, sizeof(op));
    op.pRecipientPrivateKey     = &privKey;
    op.inputData.dataLenInBytes = KEY_BYTES;
    op.inputData.pData          = uCt;

    CpaFlatBuffer outBuf = { .dataLenInBytes = KEY_BYTES, .pData = uPt };

    for (int i = 0; i < THRU_ITERS; i++) {
        long long t0 = nowNs();
        doDecrypt(&op, &outBuf);
        a->ns[i] = nowNs() - t0;
    }

    qaeMemFreeNUMA((void **)&uN);
    qaeMemFreeNUMA((void **)&uD);
    qaeMemFreeNUMA((void **)&uCt);
    qaeMemFreeNUMA((void **)&uPt);
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
    printf("=== bench_rsa_decrypt: QAT RSA-%d decrypt (Type-1, pure C) ===\n\n",
           KEY_BYTES * 8);

    initTestVectors();

    if (initQat() != 0) return 1;

    Cpa8U *uN   = qaeMemAllocNUMA(KEY_BYTES, 0, 64);
    Cpa8U *uD   = qaeMemAllocNUMA(KEY_BYTES, 0, 64);
    Cpa8U *uCt  = qaeMemAllocNUMA(KEY_BYTES, 0, 64);
    Cpa8U *uPt  = qaeMemAllocNUMA(KEY_BYTES, 0, 64);

    memcpy(uN,  g_modN,      KEY_BYTES);
    memcpy(uD,  g_privD,     KEY_BYTES);
    memcpy(uCt, g_ciphertext, KEY_BYTES);

    CpaCyRsaPrivateKeyRep1 keyRep1;
    memset(&keyRep1, 0, sizeof(keyRep1));
    keyRep1.modulusN.dataLenInBytes        = KEY_BYTES;
    keyRep1.modulusN.pData                 = uN;
    keyRep1.privateExponentD.dataLenInBytes = KEY_BYTES;
    keyRep1.privateExponentD.pData         = uD;

    CpaCyRsaPrivateKey privKey;
    memset(&privKey, 0, sizeof(privKey));
    privKey.version            = CPA_CY_RSA_VERSION_TWO_PRIME;
    privKey.privateKeyRepType  = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1;
    privKey.privateKeyRep1     = keyRep1;

    CpaCyRsaDecryptOpData op;
    memset(&op, 0, sizeof(op));
    op.pRecipientPrivateKey          = &privKey;
    op.inputData.dataLenInBytes      = KEY_BYTES;
    op.inputData.pData               = uCt;

    CpaFlatBuffer outBuf = { .dataLenInBytes = KEY_BYTES, .pData = uPt };

    printf("Warming up (%d iters)...\n", WARMUP_ITERS);
    for (int i = 0; i < WARMUP_ITERS; i++) {
        if (doDecrypt(&op, &outBuf) != 0) {
            fprintf(stderr, "Warmup failed at iter %d\n", i);
            goto cleanup;
        }
    }

    printf("Latency benchmark (%d iters)...\n", LAT_ITERS);
    long long *latNs = malloc(LAT_ITERS * sizeof(long long));

    long long wallStart = nowNs();
    for (int i = 0; i < LAT_ITERS; i++) {
        long long t0 = nowNs();
        doDecrypt(&op, &outBuf);
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
        pthread_create(&thruTh[t], NULL, rsaDecThruWorker, &thruA[t]);
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
    qaeMemFreeNUMA((void **)&uN);
    qaeMemFreeNUMA((void **)&uD);
    qaeMemFreeNUMA((void **)&uCt);
    qaeMemFreeNUMA((void **)&uPt);
    teardownQat();
    printf("\nDone.\n");
    return 0;
}
