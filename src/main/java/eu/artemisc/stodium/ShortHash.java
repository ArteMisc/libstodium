package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Size;

import org.abstractj.kalium.Sodium;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import eu.artemisc.stodium.Stodium;

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
    public static final int BYTES = 8;
    public static final int KEYBYTES = 16;

    @NonNull
    static Long shorthash(@NonNull final byte[] srcIn,
                          @NonNull @Size(KEYBYTES) final byte[] srcKey)
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

    static void shorthash(@NonNull @Size(BYTES) final byte[] dstHash,
                          @NonNull final byte[] srcIn,
                          @NonNull @Size(KEYBYTES) final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(dstHash.length, BYTES, "ShortHash.BYTES");
        Stodium.checkSize(srcKey.length, KEYBYTES, "ShortHash.KEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_shorthash(dstHash, srcIn, srcIn.length, srcKey));
    }
}
