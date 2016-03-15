package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

/**
 * Curve25519 wraps calls to crypto_scalarmult*.
 *
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
    public static final int SCALAR_BYTES = Sodium.crypto_scalarmult_scalarbytes();

    public static final String PRIMITIVE = Sodium.crypto_scalarmult_primitive();

    // wrappers

    //
    // scalar_mult*
    //

    /**
     *
     * @param dst
     * @param src
     * @param groupElement
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void scalarMult(@NonNull final byte[] dst,
                                  @NonNull final byte[] src,
                                  @NonNull final byte[] groupElement)
            throws StodiumException {
        Stodium.checkSize(dst.length, SCALAR_BYTES, "Curve25519.SCALAR_BYTES");
        Stodium.checkSize(src.length, SCALAR_BYTES, "Curve25519.SCALAR_BYTES");
        Stodium.checkSize(groupElement.length, SCALAR_BYTES, "Curve25519.SCALAR_BYTES");
        Stodium.checkStatus(Sodium.crypto_scalarmult_curve25519(dst, src,
                groupElement));
    }

    /**
     *
     * @param dst
     * @param src
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void scalarMultBase(@NonNull final byte[] dst,
                                      @NonNull final byte[] src)
            throws StodiumException {
        Stodium.checkSize(dst.length, SCALAR_BYTES, "Curve25519.SCALAR_BYTES");
        Stodium.checkSize(src.length, SCALAR_BYTES, "Curve25519.SCALAR_BYTES");
        Stodium.checkStatus(Sodium.crypto_scalarmult_base(dst, src));
    }

    //
    // convert curve
    //

    /**
     *
     * @param dstPublic
     * @param srcPrivate
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void x25519PrivateToPublic(@NonNull final byte[] dstPublic,
                                             @NonNull final byte[] srcPrivate)
            throws StodiumException {
        scalarMultBase(dstPublic, srcPrivate);
    }
}
