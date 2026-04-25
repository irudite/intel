/*
 * qat_rsa_jni.c
 *
 * JNI wrapper for QAT RSA encrypt/decrypt on a single endpoint.
 * This is the "hello QAT crypto" JNI version.
 *
 * Compile:
 *   javac -h . com/lehigh/qat/QatRsa.java
 *   gcc -shared -fpic -o libqatrsa.so qat_rsa_jni.c \
 *       -I${JAVA_HOME}/include \
 *       -I${JAVA_HOME}/include/linux \
 *       -I/usr/include/qat \
 *       -lqat -lusdm -lpthread
 *
 * Run:
 *   sudo java -Djava.library.path=. com.lehigh.qat.QatRsa
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_im.h"
#include "cpa_cy_rsa.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"

/* ================================================================
 * Global state
 * ================================================================ */
#define QAT_MAX_INSTANCES 64
static CpaInstanceHandle g_cyInst[QAT_MAX_INSTANCES];
static Cpa16U g_numInst = 0;
static int g_initialized = 0;
static pthread_t g_pollThread;
static volatile int g_keepPolling = 0;
static volatile Cpa32U g_instRR = 0; /* round-robin index */

static CpaInstanceHandle pickInstance(void)
{
    Cpa32U idx = __atomic_fetch_add(&g_instRR, 1, __ATOMIC_RELAXED) % g_numInst;
    return g_cyInst[idx];
}

/* Simple completion structure for async callback */
typedef struct {
    volatile int complete;
    CpaStatus status;
} QatCompletion;

/* ================================================================
 * Polling thread
 * ================================================================ */
static void *pollingLoop(void *arg)
{
    (void)arg;
    while (g_keepPolling) {
        for (Cpa16U i = 0; i < g_numInst; i++)
            icp_sal_CyPollInstance(g_cyInst[i], 0);
        usleep(50);
    }
    return NULL;
}

/* ================================================================
 * RSA encrypt callback
 *
 * QAT calls this when the hardware finishes the RSA operation.
 * We set the completion flag so the calling thread knows
 * the result is ready.
 * ================================================================ */
static void rsaEncryptCallback(
    void *pCallbackTag,
    CpaStatus status,
    void *pOpData,
    CpaFlatBuffer *pOutputData)
{
    QatCompletion *comp = (QatCompletion *)pCallbackTag;
    if (comp) {
        comp->status = status;
        comp->complete = 1;
    }
}

/* ================================================================
 * RSA decrypt callback
 * ================================================================ */
static void rsaDecryptCallback(
    void *pCallbackTag,
    CpaStatus status,
    void *pOpData,
    CpaFlatBuffer *pOutputData)
{
    QatCompletion *comp = (QatCompletion *)pCallbackTag;
    if (comp) {
        comp->status = status;
        comp->complete = 1;
    }
}

/* ================================================================
 * JNI: initQat()
 *
 * Same sequence as hello_qat.c:
 *   1. Start SAL
 *   2. Get instances
 *   3. Set address translation
 *   4. Start instance
 *   5. Start polling thread
 *
 * Returns 0 on success, negative on failure.
 * ================================================================ */
JNIEXPORT jint JNICALL Java_com_lehigh_qat_QatRsa_initQat
  (JNIEnv *env, jobject obj)
{
    CpaStatus status;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;

    if (g_initialized) return 0;

    /* Step 1: Start SAL */
    status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status) {
        fprintf(stderr, "icp_sal_userStartMultiProcess failed: %d\n", status);
        return -1;
    }

    /* Step 2: Get first crypto instance */
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances == 0) {
        fprintf(stderr, "No crypto instances found\n");
        icp_sal_userStop();
        return -2;
    }

    if (numInstances > QAT_MAX_INSTANCES)
        numInstances = QAT_MAX_INSTANCES;

    instances = malloc(numInstances * sizeof(CpaInstanceHandle));
    status = cpaCyGetInstances(numInstances, instances);
    if (CPA_STATUS_SUCCESS != status) {
        free(instances);
        icp_sal_userStop();
        return -3;
    }

    g_numInst = numInstances;
    memcpy(g_cyInst, instances, numInstances * sizeof(CpaInstanceHandle));
    free(instances);

    /* Steps 3-4: Address translation and start all instances */
    for (Cpa16U i = 0; i < g_numInst; i++) {
        status = cpaCySetAddressTranslation(g_cyInst[i], qaeVirtToPhysNUMA);
        if (CPA_STATUS_SUCCESS != status) {
            icp_sal_userStop();
            return -4;
        }
        status = cpaCyStartInstance(g_cyInst[i]);
        if (CPA_STATUS_SUCCESS != status) {
            icp_sal_userStop();
            return -5;
        }
    }

    /* Step 5: Start polling thread */
    g_keepPolling = 1;
    if (pthread_create(&g_pollThread, NULL, pollingLoop, NULL) != 0) {
        cpaCyStopInstance(g_cyInst);
        icp_sal_userStop();
        return -6;
    }

    g_initialized = 1;
    printf("QAT RSA JNI: initialized with %u instance(s)\n", g_numInst);
    return 0;
}

/* ================================================================
 * JNI: rsaEncrypt(byte[] modN, byte[] expE, byte[] plaintext)
 *
 * Performs RSA Type 1 (public key) encrypt:
 *   ciphertext = plaintext ^ E mod N
 *
 * Arguments from Java are raw big-endian byte arrays:
 *   modN      = RSA modulus N
 *   expE      = RSA public exponent E
 *   plaintext = data to encrypt (must be < N, no padding here)
 *
 * Returns: encrypted byte array, or null on failure.
 *
 * Memory flow:
 *   Java heap -> copy to USDM (pinned) -> QAT DMA -> copy back to Java heap
 * ================================================================ */
JNIEXPORT jbyteArray JNICALL Java_com_lehigh_qat_QatRsa_rsaEncrypt
  (JNIEnv *env, jobject obj,
   jbyteArray jModN, jbyteArray jExpE, jbyteArray jPlaintext)
{
    CpaStatus status;
    jsize nLen = (*env)->GetArrayLength(env, jModN);
    jsize eLen = (*env)->GetArrayLength(env, jExpE);
    jsize ptLen = (*env)->GetArrayLength(env, jPlaintext);

    /* Allocate USDM (physically contiguous) memory.
     * QAT hardware reads/writes via DMA, so all buffers
     * must be in pinned physical memory, not Java heap. */
    Cpa8U *usdmN  = qaeMemAllocNUMA(nLen,  0, 64);
    Cpa8U *usdmE  = qaeMemAllocNUMA(eLen,  0, 64);
    Cpa8U *usdmPt = qaeMemAllocNUMA(ptLen, 0, 64);
    Cpa8U *usdmCt = qaeMemAllocNUMA(nLen,  0, 64); /* output is modulus-sized */

    if (!usdmN || !usdmE || !usdmPt || !usdmCt) {
        fprintf(stderr, "USDM alloc failed\n");
        goto encrypt_cleanup;
    }

    /* Copy from Java heap to USDM */
    (*env)->GetByteArrayRegion(env, jModN,      0, nLen,  (jbyte*)usdmN);
    (*env)->GetByteArrayRegion(env, jExpE,       0, eLen,  (jbyte*)usdmE);
    (*env)->GetByteArrayRegion(env, jPlaintext,  0, ptLen, (jbyte*)usdmPt);
    memset(usdmCt, 0, nLen);

    /* Build RSA public key structure */
    CpaCyRsaPublicKey pubKey;
    memset(&pubKey, 0, sizeof(pubKey));
    pubKey.modulusN.dataLenInBytes = nLen;
    pubKey.modulusN.pData = usdmN;
    pubKey.publicExponentE.dataLenInBytes = eLen;
    pubKey.publicExponentE.pData = usdmE;

    /* Build encrypt operation data */
    CpaCyRsaEncryptOpData opData;
    memset(&opData, 0, sizeof(opData));
    opData.pPublicKey = &pubKey;
    opData.inputData.dataLenInBytes = ptLen;
    opData.inputData.pData = usdmPt;

    /* Output buffer */
    CpaFlatBuffer outputBuf;
    outputBuf.dataLenInBytes = nLen;
    outputBuf.pData = usdmCt;

    /* Completion tracking */
    QatCompletion comp = { .complete = 0, .status = CPA_STATUS_SUCCESS };

    /* Submit RSA encrypt to hardware */
    status = cpaCyRsaEncrypt(
        pickInstance(),
        rsaEncryptCallback,  /* async callback */
        (void *)&comp,       /* callback tag */
        &opData,             /* operation data */
        &outputBuf);         /* output buffer */

    if (CPA_STATUS_SUCCESS != status) {
        fprintf(stderr, "cpaCyRsaEncrypt failed: %d\n", status);
        goto encrypt_cleanup;
    }

    /* Wait for hardware to complete */
    while (!comp.complete) {
        usleep(10);
    }

    if (CPA_STATUS_SUCCESS != comp.status) {
        fprintf(stderr, "RSA encrypt callback status: %d\n", comp.status);
        goto encrypt_cleanup;
    }

    /* Copy result from USDM back to Java heap */
    jbyteArray jResult = (*env)->NewByteArray(env, nLen);
    (*env)->SetByteArrayRegion(env, jResult, 0, nLen, (jbyte*)usdmCt);

    /* Free USDM memory */
    qaeMemFreeNUMA((void **)&usdmN);
    qaeMemFreeNUMA((void **)&usdmE);
    qaeMemFreeNUMA((void **)&usdmPt);
    qaeMemFreeNUMA((void **)&usdmCt);

    return jResult;

encrypt_cleanup:
    if (usdmN)  qaeMemFreeNUMA((void **)&usdmN);
    if (usdmE)  qaeMemFreeNUMA((void **)&usdmE);
    if (usdmPt) qaeMemFreeNUMA((void **)&usdmPt);
    if (usdmCt) qaeMemFreeNUMA((void **)&usdmCt);
    return NULL;
}

/* ================================================================
 * JNI: rsaDecrypt(byte[] modN, byte[] expD, byte[] ciphertext)
 *
 * Performs RSA Type 1 (private key) decrypt:
 *   plaintext = ciphertext ^ D mod N
 *
 * Uses CRT (Chinese Remainder Theorem) version for speed
 * when p, q, dP, dQ, qInv are available. This version uses
 * the simpler Type 1 (non-CRT) for clarity.
 * ================================================================ */
JNIEXPORT jbyteArray JNICALL Java_com_lehigh_qat_QatRsa_rsaDecrypt
  (JNIEnv *env, jobject obj,
   jbyteArray jModN, jbyteArray jExpD, jbyteArray jCiphertext)
{
    CpaStatus status;
    jsize nLen = (*env)->GetArrayLength(env, jModN);
    jsize dLen = (*env)->GetArrayLength(env, jExpD);
    jsize ctLen = (*env)->GetArrayLength(env, jCiphertext);

    Cpa8U *usdmN  = qaeMemAllocNUMA(nLen,  0, 64);
    Cpa8U *usdmD  = qaeMemAllocNUMA(dLen,  0, 64);
    Cpa8U *usdmCt = qaeMemAllocNUMA(ctLen, 0, 64);
    Cpa8U *usdmPt = qaeMemAllocNUMA(nLen,  0, 64);

    if (!usdmN || !usdmD || !usdmCt || !usdmPt) {
        fprintf(stderr, "USDM alloc failed\n");
        goto decrypt_cleanup;
    }

    (*env)->GetByteArrayRegion(env, jModN,       0, nLen,  (jbyte*)usdmN);
    (*env)->GetByteArrayRegion(env, jExpD,        0, dLen,  (jbyte*)usdmD);
    (*env)->GetByteArrayRegion(env, jCiphertext,  0, ctLen, (jbyte*)usdmCt);
    memset(usdmPt, 0, nLen);

    /* RSA Type 1 private key: just N and D */
    CpaCyRsaPrivateKeyRep1 keyRep1;
    memset(&keyRep1, 0, sizeof(keyRep1));
    keyRep1.modulusN.dataLenInBytes = nLen;
    keyRep1.modulusN.pData = usdmN;
    keyRep1.privateExponentD.dataLenInBytes = dLen;
    keyRep1.privateExponentD.pData = usdmD;

    CpaCyRsaPrivateKey privKey;
    memset(&privKey, 0, sizeof(privKey));
    privKey.version = CPA_CY_RSA_VERSION_TWO_PRIME;
    privKey.privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1;
    privKey.privateKeyRep1 = keyRep1;

    CpaCyRsaDecryptOpData opData;
    memset(&opData, 0, sizeof(opData));
    opData.pRecipientPrivateKey = &privKey;
    opData.inputData.dataLenInBytes = ctLen;
    opData.inputData.pData = usdmCt;

    CpaFlatBuffer outputBuf;
    outputBuf.dataLenInBytes = nLen;
    outputBuf.pData = usdmPt;

    QatCompletion comp = { .complete = 0, .status = CPA_STATUS_SUCCESS };

    status = cpaCyRsaDecrypt(
        pickInstance(),
        rsaDecryptCallback,
        (void *)&comp,
        &opData,
        &outputBuf);

    if (CPA_STATUS_SUCCESS != status) {
        fprintf(stderr, "cpaCyRsaDecrypt failed: %d\n", status);
        goto decrypt_cleanup;
    }

    while (!comp.complete) {
        usleep(10);
    }

    if (CPA_STATUS_SUCCESS != comp.status) {
        fprintf(stderr, "RSA decrypt callback status: %d\n", comp.status);
        goto decrypt_cleanup;
    }

    jbyteArray jResult = (*env)->NewByteArray(env, nLen);
    (*env)->SetByteArrayRegion(env, jResult, 0, nLen, (jbyte*)usdmPt);

    qaeMemFreeNUMA((void **)&usdmN);
    qaeMemFreeNUMA((void **)&usdmD);
    qaeMemFreeNUMA((void **)&usdmCt);
    qaeMemFreeNUMA((void **)&usdmPt);

    return jResult;

decrypt_cleanup:
    if (usdmN)  qaeMemFreeNUMA((void **)&usdmN);
    if (usdmD)  qaeMemFreeNUMA((void **)&usdmD);
    if (usdmCt) qaeMemFreeNUMA((void **)&usdmCt);
    if (usdmPt) qaeMemFreeNUMA((void **)&usdmPt);
    return NULL;
}

/* ================================================================
 * JNI: shutdownQat()
 * ================================================================ */
JNIEXPORT void JNICALL Java_com_lehigh_qat_QatRsa_shutdownQat
  (JNIEnv *env, jobject obj)
{
    if (!g_initialized) return;

    g_keepPolling = 0;
    pthread_join(g_pollThread, NULL);
    for (Cpa16U i = 0; i < g_numInst; i++)
        cpaCyStopInstance(g_cyInst[i]);
    icp_sal_userStop();
    g_numInst = 0;
    g_initialized = 0;
    printf("QAT RSA JNI: shutdown\n");
}
