package eu.artemisc.stodium;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;

/**
 * RandomBytes builds on top of libsodium's random_bytes as its CSPRNG.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class RandomBytes {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private RandomBytes() {}

    /**
     * nextBytes fills the provided buffer with random bytes, using Sodium's
     * {@code randombytes_buf(void*, size_t)} function.
     *
     * FIXME this method call does not work
     *
     * @param buffer
     */
    public static void nextBytes(@NotNull final byte[] buffer) {
        Sodium.randombytes_buf(buffer, buffer.length);
    }
}
