package com.lehigh.qat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * RsaJniBenchmark
 *
 * Latency and throughput benchmark for QAT RSA-2048 encrypt via JNI.
 * Calls QatRsa.rsaEncrypt() — the real JNI bridge — so each timed
 * iteration crosses the Java/C boundary, does GetByteArrayRegion for
 * modN + expE + plaintext, allocates USDM, submits to QAT, waits,
 * frees USDM, and does SetByteArrayRegion back to the Java heap.
 *
 * The delta between these numbers and bench_rsa_native is the total
 * JNI overhead: call transition + 3 inbound copies + 1 outbound copy
 * + per-call USDM alloc/free.
 *
 * Build steps:
 *   1. Compile (from lab_work/):
 *        javac com/lehigh/qat/QatRsa.java com/lehigh/qat/RsaJniBenchmark.java
 *   2. Run:
 *        sudo java -Djava.library.path=. com.lehigh.qat.RsaJniBenchmark
 */
public class RsaJniBenchmark {

    private static final int KEY_BYTES     = 256;    /* RSA-2048              */
    private static final int WARMUP_ITERS  = 200;
    private static final int LAT_ITERS     = 5000;   /* per-op timing samples */
    private static final int THRU_ITERS    = 10000;  /* ops per thread        */
    private static final int THRU_THREADS  = 16;     /* concurrent threads    */

    /* Convert BigInteger to fixed-width big-endian byte array */
    private static byte[] toFixedBytes(BigInteger val, int len) {
        byte[] raw = val.toByteArray();
        if (raw.length == len) return raw;
        if (raw.length > len) return Arrays.copyOfRange(raw, raw.length - len, raw.length);
        byte[] padded = new byte[len];
        System.arraycopy(raw, 0, padded, len - raw.length, raw.length);
        return padded;
    }

    private static int cmp(long a, long b) { return Long.compare(a, b); }

    private static void printStats(String label, long[] ns, int n, double elapsedSec) {
        long[] sorted = Arrays.copyOf(ns, n);
        Arrays.sort(sorted);

        long sum = 0;
        for (long v : sorted) sum += v;

        double mean = sum / (double) n / 1000.0;
        double min  = sorted[0]                   / 1000.0;
        double p50  = sorted[n * 50 / 100]        / 1000.0;
        double p95  = sorted[n * 95 / 100]        / 1000.0;
        double p99  = sorted[n * 99 / 100]        / 1000.0;
        double p999 = sorted[n * 999 / 1000]      / 1000.0;
        double max  = sorted[n - 1]               / 1000.0;
        double ops  = n / elapsedSec;

        System.out.printf("%n--- %s ---%n", label);
        System.out.printf("  iterations  : %d%n",      n);
        System.out.printf("  elapsed     : %.3f s%n",  elapsedSec);
        System.out.printf("  throughput  : %.0f ops/sec%n", ops);
        System.out.printf(
            "  latency (us): mean=%.1f  min=%.1f  p50=%.1f  p95=%.1f  p99=%.1f  p99.9=%.1f  max=%.1f%n",
            mean, min, p50, p95, p99, p999, max);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== RsaJniBenchmark: QAT RSA-2048 encrypt via JNI ===");
        System.out.println("(JNI overhead = delta vs. bench_rsa_native)");
        System.out.println();

        /* Init QAT via JNI */
        QatRsa qat = new QatRsa();
        int rc = qat.initQat();
        if (rc != 0) {
            System.err.println("initQat() failed, rc=" + rc);
            System.exit(1);
        }

        /* Generate RSA-2048 key in Java, extract raw byte arrays.
         * modN and expE are passed on every encrypt call — same pattern
         * as the current JNI bridge — so the benchmark includes those copies. */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_BYTES * 8);
        KeyPair kp = kpg.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        byte[] modN = toFixedBytes(pub.getModulus(),         KEY_BYTES);
        byte[] expE = toFixedBytes(pub.getPublicExponent(),  KEY_BYTES);

        /* Plaintext: small value to guarantee < N for raw RSA */
        byte[] plaintext = new byte[KEY_BYTES];
        plaintext[KEY_BYTES - 1] = 0x42;
        plaintext[KEY_BYTES - 2] = 0x41;

        /* Warmup */
        System.out.printf("Warming up (%d iters)...%n", WARMUP_ITERS);
        for (int i = 0; i < WARMUP_ITERS; i++) {
            byte[] ct = qat.rsaEncrypt(modN, expE, plaintext);
            if (ct == null) {
                System.err.println("rsaEncrypt returned null at warmup iter " + i);
                qat.shutdownQat();
                System.exit(1);
            }
        }

        /* --- Latency benchmark --- */
        System.out.printf("Latency benchmark (%d iters)...%n", LAT_ITERS);
        long[] latNs = new long[LAT_ITERS];

        long wallStart = System.nanoTime();
        for (int i = 0; i < LAT_ITERS; i++) {
            long t0 = System.nanoTime();
            byte[] ct = qat.rsaEncrypt(modN, expE, plaintext);
            latNs[i] = System.nanoTime() - t0;
            if (ct == null) {
                System.err.println("rsaEncrypt returned null at latency iter " + i);
                qat.shutdownQat();
                System.exit(1);
            }
        }
        long wallEnd = System.nanoTime();

        printStats("Latency", latNs, LAT_ITERS,
                   (wallEnd - wallStart) / 1e9);

        /* --- Throughput benchmark: multi-threaded to saturate QAT --- */
        System.out.printf("%nThroughput benchmark (%d threads x %d iters)...%n",
                          THRU_THREADS, THRU_ITERS);

        final byte[] fModN      = modN;
        final byte[] fExpE      = expE;
        final byte[] fPlaintext = plaintext;
        final QatRsa fQat       = qat;

        ExecutorService pool = Executors.newFixedThreadPool(THRU_THREADS);
        @SuppressWarnings("unchecked")
        Future<long[]>[] futures = new Future[THRU_THREADS];

        long thruStart = System.nanoTime();
        for (int t = 0; t < THRU_THREADS; t++) {
            futures[t] = pool.submit(() -> {
                long[] ns = new long[THRU_ITERS];
                for (int i = 0; i < THRU_ITERS; i++) {
                    long t0 = System.nanoTime();
                    byte[] ct = fQat.rsaEncrypt(fModN, fExpE, fPlaintext);
                    ns[i] = System.nanoTime() - t0;
                    if (ct == null) throw new RuntimeException("rsaEncrypt returned null");
                }
                return ns;
            });
        }

        long[] combined = new long[THRU_THREADS * THRU_ITERS];
        for (int t = 0; t < THRU_THREADS; t++) {
            long[] perThread = futures[t].get();
            System.arraycopy(perThread, 0, combined, t * THRU_ITERS, THRU_ITERS);
        }
        long thruEnd = System.nanoTime();
        pool.shutdown();

        printStats("Throughput (multi-threaded)", combined, THRU_THREADS * THRU_ITERS,
                   (thruEnd - thruStart) / 1e9);

        qat.shutdownQat();
        System.out.println("\nDone.");
    }
}
