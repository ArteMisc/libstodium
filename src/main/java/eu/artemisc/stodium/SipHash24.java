package eu.artemisc.stodium;

import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * SipHash24 wraps calls to sodium's crypto_shorthash_siphash API, which
 * implements the SipHash-2-4 specification.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class SipHash24 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private SipHash24() {}

    // constants
    public static final int BYTES    = Sodium.crypto_shorthash_siphash24_bytes();
    public static final int KEYBYTES = Sodium.crypto_shorthash_siphash24_keybytes();

    /**
     *
     * @param srcIn
     * @param srcKey
     * @return
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    @NonNull @CheckResult
    static Long shorthash(@NonNull final byte[] srcIn,
                          @NonNull final byte[] srcKey)
            throws StodiumException {
        Stodium.checkSize(srcKey.length, KEYBYTES, "SipHash24.KEYBYTES");

        byte[] dst = new byte[BYTES];
        Stodium.checkStatus(
                Sodium.crypto_shorthash_siphash24(dst, srcIn, srcIn.length, srcKey));

        // Return as long
        return ByteBuffer.wrap(dst)
                .order(ByteOrder.BIG_ENDIAN)
                .getLong();
    }

    /**
     *
     * @param dstHash
     * @param srcIn
     * @param srcKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    static void shorthash(@NonNull final byte[] dstHash,
                          @NonNull final byte[] srcIn,
                          @NonNull final byte[] srcKey)
            throws StodiumException {
        Stodium.checkSize(dstHash.length, BYTES, "SipHash24.BYTES");
        Stodium.checkSize(srcKey.length, KEYBYTES, "SipHash24.KEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_shorthash_siphash24(dstHash, srcIn, srcIn.length, srcKey));
    }
}
