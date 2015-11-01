package eu.artemisc.strodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

/**
 * RandomBytes builds on top of libsodium's random_bytes as its CSPRNG.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class RandomBytes {
    // dependency on Sodium
    static {
        Sodium.sodium_init();
    }

    // hide constructor
    private RandomBytes() {}

    /**
     * nextBytes fills the provided buffer with random bytes, using Sodium's
     * {@code randombytes_buf(void*, size_t)} function.
     *
     * FIXME this method call does not work
     *
     * @param buffer
     */
    public static void nextBytes(@NonNull final byte[] buffer) {
        Sodium.randombytes_buf(buffer, buffer.length);
    }

}
