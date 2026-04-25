package com.lehigh.qat;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

/**
 * QatRsa - JNI bridge to QAT hardware RSA encrypt/decrypt.
 *
 * Build steps:
 *   1. Compile Java and generate JNI header:
 *      javac -h . com/lehigh/qat/QatRsa.java
 *
 *   2. Compile C shared library:
 *      gcc -shared -fpic -o libqatrsa.so qat_rsa_jni.c \
 *          -I${JAVA_HOME}/include \
 *          -I${JAVA_HOME}/include/linux \
 *          -I/usr/include/qat \
 *          -lqat -lusdm -lpthread
 *
 *   3. Run:
 *      sudo java -Djava.library.path=. com.lehigh.qat.QatRsa
 */
public class QatRsa {

    static {
        System.loadLibrary("qatrsa");
    }

    /* ---- Native methods ---- */

    /**
     * Initialize QAT: start SAL, grab one crypto instance,
     * start polling thread.
     * @return 0 on success, negative error code on failure
     */
    public native int initQat();

    /**
     * RSA encrypt using public key (Type 1).
     * ciphertext = plaintext ^ E mod N
     *
     * @param modN      RSA modulus N, big-endian byte array
     * @param expE      RSA public exponent E, big-endian byte array
     * @param plaintext data to encrypt (raw, no padding, must be < N)
     * @return ciphertext byte array, or null on failure
     */
    public native byte[] rsaEncrypt(byte[] modN, byte[] expE, byte[] plaintext);

    /**
     * RSA decrypt using private key (Type 1, non-CRT).
     * plaintext = ciphertext ^ D mod N
     *
     * @param modN       RSA modulus N, big-endian byte array
     * @param expD       RSA private exponent D, big-endian byte array
     * @param ciphertext data to decrypt
     * @return plaintext byte array, or null on failure
     */
    public native byte[] rsaDecrypt(byte[] modN, byte[] expD, byte[] ciphertext);

    /**
     * Shutdown QAT: stop polling, stop instance, stop SAL.
     */
    public native void shutdownQat();

    /* ---- Helper: BigInteger to fixed-size big-endian byte array ---- */
    private static byte[] toFixedBytes(BigInteger val, int len) {
        byte[] raw = val.toByteArray();
        if (raw.length == len) return raw;
        if (raw.length > len) {
            /* strip leading zero byte that BigInteger adds for sign */
            return Arrays.copyOfRange(raw, raw.length - len, raw.length);
        }
        /* pad with leading zeros */
        byte[] padded = new byte[len];
        System.arraycopy(raw, 0, padded, len - raw.length, raw.length);
        return padded;
    }

    /* ---- Self-test ---- */
    public static void main(String[] args) throws Exception {
        QatRsa qat = new QatRsa();

        /* Step 1: Init QAT */
        int rc = qat.initQat();
        if (rc != 0) {
            System.err.println("QAT init failed, rc=" + rc);
            System.exit(1);
        }

        /* Step 2: Generate an RSA 2048 key pair using Java */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

        BigInteger N = pub.getModulus();
        BigInteger E = pub.getPublicExponent();
        BigInteger D = priv.getPrivateExponent();

        int keyBytes = N.bitLength() / 8; /* 256 for RSA-2048 */

        byte[] modN = toFixedBytes(N, keyBytes);
        byte[] expE = toFixedBytes(E, keyBytes);
        byte[] expD = toFixedBytes(D, keyBytes);

        /* Step 3: Create a small plaintext (raw RSA, no padding) */
        byte[] plaintext = new byte[keyBytes];
        /* Put "Hello QAT" at the end, padded with zeros on the left.
         * This ensures plaintext < N for raw RSA. */
        byte[] msg = "Hello QAT RSA!".getBytes();
        System.arraycopy(msg, 0, plaintext, keyBytes - msg.length, msg.length);

        System.out.println("Plaintext:  " + bytesToHex(plaintext, 20));

        /* Step 4: Encrypt with QAT hardware */
        long t0 = System.nanoTime();
        byte[] ciphertext = qat.rsaEncrypt(modN, expE, plaintext);
        long t1 = System.nanoTime();

        if (ciphertext == null) {
            System.err.println("Encrypt returned null");
            qat.shutdownQat();
            System.exit(1);
        }
        System.out.println("Ciphertext: " + bytesToHex(ciphertext, 20));
        System.out.println("Encrypt time: " + (t1 - t0) / 1000 + " us");

        /* Step 5: Decrypt with QAT hardware */
        long t2 = System.nanoTime();
        byte[] decrypted = qat.rsaDecrypt(modN, expD, ciphertext);
        long t3 = System.nanoTime();

        if (decrypted == null) {
            System.err.println("Decrypt returned null");
            qat.shutdownQat();
            System.exit(1);
        }
        System.out.println("Decrypted:  " + bytesToHex(decrypted, 20));
        System.out.println("Decrypt time: " + (t3 - t2) / 1000 + " us");

        /* Step 6: Verify round-trip */
        if (Arrays.equals(plaintext, decrypted)) {
            System.out.println("\nSUCCESS: round-trip matched.");
        } else {
            System.out.println("\nFAILURE: mismatch.");
        }

        /* Step 7: Shutdown */
        qat.shutdownQat();
    }

    private static String bytesToHex(byte[] bytes, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(bytes.length, maxBytes);
        for (int i = 0; i < limit; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > maxBytes) sb.append("...");
        return sb.toString();
    }
}
