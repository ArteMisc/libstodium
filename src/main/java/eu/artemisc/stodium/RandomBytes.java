package eu.artemisc.stodium;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

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
     * @param buffer
     * @throws ReadOnlyBufferException
     */
    public static void nextBytes(final @NotNull ByteBuffer buffer) {
        Stodium.checkDestinationWritable(buffer, "RANDOM buffer");
        StodiumJNI.randombytes_buf(buffer);
    }
}
