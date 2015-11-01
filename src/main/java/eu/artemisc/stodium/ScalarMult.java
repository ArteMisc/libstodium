package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

/**
 * ScalarMult wraps calls to crypto_scalarmult*.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class ScalarMult {
    // block constructor
    private ScalarMult() {}

    public static int SCALAR_BYTES = 32;

    private static void checkKeyLengths(final int pubKeyLen,
                                        final int privKeyLen)
            throws SecurityException {
        if (pubKeyLen != SCALAR_BYTES) {
            throw new SecurityException("ScalarMult: pubKeyLen != SCALAR_BYTES. " +
                    pubKeyLen + " != " + SCALAR_BYTES);
        }
        if (privKeyLen != SCALAR_BYTES) {
            throw new SecurityException("ScalarMult: privKeyLen != SCALAR_BYTES. " +
                    privKeyLen + " != " + SCALAR_BYTES);
        }
    }


    /**
     *
     * @param dst
     * @param src
     * @param groupElement
     * @throws SecurityException
     */
    public static void scalarMult(@NonNull final byte[] dst,
                                  @NonNull final byte[] src,
                                  @NonNull final byte[] groupElement)
            throws SecurityException {
        checkKeyLengths(dst.length, src.length);
        if (groupElement.length != SCALAR_BYTES) {
            throw new SecurityException("ScalarMult: privKeyLen != SCALAR_BYTES. " +
                    groupElement.length + " != " + SCALAR_BYTES);
        }
        Stodium.checkStatus(Sodium.crypto_scalarmult_curve25519(dst, src,
                groupElement));
    }

    /**
     *
     * @param dst
     * @param src
     * @throws SecurityException
     */
    public static void scalarMultBase(@NonNull final byte[] dst,
                                      @NonNull final byte[] src)
            throws SecurityException {
        checkKeyLengths(dst.length, src.length);
        Stodium.checkStatus(Sodium.crypto_scalarmult_base(dst, src));
    }

    /**
     * curve25519PrivateToPublic is a simple wrapper that calls curve25519's
     * scalar_mult function, but with a more descriptive name.
     *
     * @param dstPublic the destination array where the computed public key will
     *                  be written to
     * @param srcPrivate The source private key for which the public key will be
     *                   calculated
     * @throws SecurityException If any of the operations fail
     */
    public static void curve25519PrivateToPublic(@NonNull final byte[] dstPublic,
                                                 @NonNull final byte[] srcPrivate)
            throws SecurityException {
        scalarMultBase(dstPublic, srcPrivate);
    }
}
