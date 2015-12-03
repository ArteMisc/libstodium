package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

/**
 * ScalarMult wraps calls to crypto_scalarmult*.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class ScalarMult {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private ScalarMult() {}

    // constants
    public static int SCALAR_BYTES = 32;

    // wrappers

    //
    // scalar_mult*
    //

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
        Stodium.checkSize(dst.length, SCALAR_BYTES, "ScalarMult.SCALAR_BYTES");
        Stodium.checkSize(src.length, SCALAR_BYTES, "ScalarMult.SCALAR_BYTES");
        Stodium.checkSize(groupElement.length, SCALAR_BYTES, "ScalarMult.SCALAR_BYTES");
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
        Stodium.checkSize(dst.length, SCALAR_BYTES, "ScalarMult.SCALAR_BYTES");
        Stodium.checkSize(src.length, SCALAR_BYTES, "ScalarMult.SCALAR_BYTES");
        Stodium.checkStatus(Sodium.crypto_scalarmult_base(dst, src));
    }

    //
    // convert curve
    //

    public static void curve25519PrivateToPublic(@NonNull final byte[] dstPublic,
                                                 @NonNull final byte[] srcPrivate)
            throws SecurityException {
        scalarMultBase(dstPublic, srcPrivate);
    }
}
