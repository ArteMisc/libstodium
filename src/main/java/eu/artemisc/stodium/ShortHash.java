package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ShortHash wraps calls to sodium's crypto_shorthash API.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class ShortHash {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private ShortHash() {}

    // constants
    public static final int BYTES = Sodium.crypto_shorthash_bytes();
    public static final int KEYBYTES = Sodium.crypto_shorthash_keybytes();

    public static final String PRIMITIVE = new String(Sodium.crypto_shorthash_primitive());

    /**
     *
     * @param srcIn
     * @param srcKey
     * @return a Long that holds the (BigEndian) representation of the resulting
     *         64-bit Hash value.
     * @throws SecurityException
     */
    @NonNull
    static Long shorthash(@NonNull final byte[] srcIn,
                          @NonNull final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(srcKey.length, KEYBYTES, "ShortHash.KEYBYTES");

        byte[] dst = new byte[BYTES];
        Stodium.checkStatus(
                Sodium.crypto_shorthash(dst, srcIn, srcIn.length, srcKey));

        // Return as long
        return ByteBuffer.wrap(dst)
                .order(ByteOrder.BIG_ENDIAN)
                .getLong();
    }

    /**
     *
     * @param dstHash The destination array to which the resulting 8-byte hash.
     *                The bytes are considered to be BigEndian.
     * @param srcIn
     * @param srcKey
     * @throws SecurityException
     */
    static void shorthash(@NonNull final byte[] dstHash,
                          @NonNull final byte[] srcIn,
                          @NonNull final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(dstHash.length, BYTES, "ShortHash.BYTES");
        Stodium.checkSize(srcKey.length, KEYBYTES, "ShortHash.KEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_shorthash(dstHash, srcIn, srcIn.length, srcKey));
    }
}
