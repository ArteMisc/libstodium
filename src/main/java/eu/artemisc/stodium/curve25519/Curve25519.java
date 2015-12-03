package eu.artemisc.stodium.curve25519;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import java.util.Random;

import eu.artemisc.stodium.Stodium;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Curve25519 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Curve25519() {}

    // constants
    public static final int BYTES = Sodium.crypto_scalarmult_bytes();
    public static final int SCALARBYTES = Sodium.crypto_scalarmult_scalarbytes();

    // wrappers

    /**
     *
     * @param dstPublicKey
     * @param srcPrivateKey
     * @throws SecurityException
     */
    /**
     * privateToPublic is a simple wrapper that calls curve25519's scalar_mult
     * function, but with a more descriptive name.
     *
     * @param dstPublic the destination array where the computed public key will
     *                  be written to
     * @param srcPrivate The source private key for which the public key will be
     *                   calculated
     * @throws SecurityException If any of the operations fail
     */
    public static void privateToPublic(@NonNull final byte[] dstPublic,
                                       @NonNull final byte[] srcPrivate)
            throws SecurityException {
        scalarMultBase(dstPublic, srcPrivate);
    }

    /**
     *
     * @param random
     * @param dstPublic
     * @param dstPrivate
     * @throws SecurityException
     */
    public static void keypair(@NonNull final Random random,
                               @NonNull final byte[] dstPublic,
                               @NonNull final byte[] dstPrivate)
            throws SecurityException {
        random.nextBytes(dstPrivate);
        privateToPublic(dstPublic, dstPrivate);
    }

    /**
     *
     * @param q
     * @param n
     * @param p
     * @throws SecurityException
     */
    public static void scalarMult(@NonNull final byte[] q,
                                  @NonNull final byte[] n,
                                  @NonNull final byte[] p)
            throws SecurityException {
        Stodium.checkSize(q.length, BYTES, "Curve25519.BYTES");
        Stodium.checkSize(n.length, SCALARBYTES, "Curve25519.SCALARBYTES");
        Stodium.checkSize(p.length, BYTES, "Curve25519.BYTES");
        Stodium.checkStatus(Sodium.crypto_scalarmult_curve25519(q, n, p));
    }

    /**
     *
     * @param q
     * @param n
     * @throws SecurityException
     */
    public static void scalarMultBase(@NonNull final byte[] q,
                                      @NonNull final byte[] n)
            throws SecurityException {
        Stodium.checkSize(q.length, BYTES, "Curve25519.BYTES");
        Stodium.checkSize(n.length, SCALARBYTES, "Curve25519.SCALARBYTES");
        Stodium.checkStatus(Sodium.crypto_scalarmult_curve25519_base(q, n));
    }
}
