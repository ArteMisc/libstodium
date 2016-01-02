package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import org.abstractj.kalium.Sodium;

import java.util.Arrays;

/**
 * GenericHash wraps calls to crypto_generichash, based on BLAKE2b.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class GenericHash {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private GenericHash() {}

    // constants
    public static final int BYTES = Sodium.crypto_generichash_bytes();
    public static final int BYTES_MIN = Sodium.crypto_generichash_bytes_min();
    public static final int BYTES_MAX = Sodium.crypto_generichash_bytes_max();
    public static final int KEYBYTES = Sodium.crypto_generichash_keybytes();
    public static final int KEYBYTES_MIN = Sodium.crypto_generichash_keybytes_min();
    public static final int KEYBYTES_MAX = Sodium.crypto_generichash_keybytes_max();

    public static final int STATE_BYTES = Sodium.crypto_generichash_statebytes();

    public static final String PRIMITIVE = new String(Sodium.crypto_generichash_primitive());

    // wrappers

    //
    // Simple API
    //

    /**
     * genericHash calculates the hash of the input using the key. The result
     * will be placed in dstHash
     *
     * @param dstHash the destination array the hash will be written to
     * @param srcInput the value that will be hashed
     * @param srcKey the key used to calculate the hash
     * @throws SecurityException
     */
    public static void genericHash(@NonNull final byte[] dstHash,
                                   @NonNull final byte[] srcInput,
                                   @Nullable final byte[] srcKey)
            throws SecurityException {
        if (srcKey == null || srcKey.length == 0) {
            genericHash(dstHash, srcInput);
            return;
        }

        Stodium.checkSize(dstHash.length, BYTES_MIN, BYTES_MAX,
                "GenericHash.BYTES_MIN", "GenericHash.BYTES_MAX");
        Stodium.checkSize(srcKey.length, KEYBYTES_MIN, KEYBYTES_MAX,
                "GenericHash.KEYBYTES_MIN", "GenericHash.KEYBYTES_MAX");
        Stodium.checkStatus(Sodium.crypto_generichash(dstHash, dstHash.length,
                srcInput, srcInput.length, srcKey, srcKey.length));
    }

    /**
     * genericHash without key, equivalent to calling
     * {@link #genericHash(byte[], byte[], byte[])} with {@code srcKey == null}
     * or {@code srcKey.length == 0}.
     *
     * @param dstHash the destination array the hash will be written to
     * @param srcInput the value that will be hashed
     * @throws SecurityException
     */
    public static void genericHash(@NonNull final byte[] dstHash,
                                   @NonNull final byte[] srcInput)
            throws SecurityException {
        Stodium.checkSize(dstHash.length, BYTES_MIN, BYTES_MAX,
                "GenericHash.BYTES_MIN", "GenericHash.BYTES_MAX");
        Stodium.checkStatus(Sodium.crypto_generichash(dstHash, dstHash.length,
                srcInput, srcInput.length, new byte[0], 0));
    }

    //
    // Streaming API
    //

    public final static class State {
        /**
         * state holds the binary representation of the crypto_generichash_state
         * value.
         */
        @NonNull private final byte[] state;
        /**
         * outlen is the number of output bytes the state should produce. It is
         * used byte genericHashFinal to validate that the number of
         * output-bytes read from the state is &lt;= State.outlen.
         */
        private final int outlen;

        /**
         * State allocates a byte array that holds the raw packed value of the C
         * crypto_generichash_state bytes.
         */
        public State(final int outlen) {
            this.state = new byte[STATE_BYTES];
            this.outlen = outlen;
        }

        /**
         * State copy-constructor. If _finish should be called on multiple
         * occasions during the streaming without losing the state, it can be
         * copied.
         *
         * @param original The original State that should be copied
         */
        public State(@NonNull final State original) {
            this.state = Arrays.copyOf(original.state, original.state.length);
            this.outlen = original.outlen;
        }
    }

    /**
     *
     * @param state
     * @param key
     * @throws SecurityException
     */
    public static void genericHashInit(@NonNull final State state,
                                       @NonNull final byte[] key)
            throws SecurityException {
        Stodium.checkSize(key.length, KEYBYTES_MIN, KEYBYTES_MAX,
                "GenericHash.KEYBYTES_MIN", "GenericHash.KEYBYTES_MAX");
        Stodium.checkSize(state.outlen, BYTES_MIN, BYTES_MAX,
                "GenericHash.BYTES_MIN", "GenericHash.BYTES_MAX");
        Stodium.checkStatus(Sodium.crypto_generichash_init(state.state,
                key, key.length, state.outlen));
    }

    /**
     *
     * @param state
     * @param in
     * @throws SecurityException
     */
    public static void genericHashUpdate(@NonNull final State state,
                                         @NonNull final byte[] in)
            throws SecurityException {
        Stodium.checkStatus(Sodium.crypto_generichash_update(
                state.state, in, in.length));
    }

    /**
     *
     * @param state
     * @param out
     * @throws SecurityException
     */
    public static void genericHashFinal(@NonNull final State state,
                                        @NonNull final byte[] out)
            throws SecurityException {
        Stodium.checkSize(out.length, 0, state.outlen, "0", "State.outlen");
        Stodium.checkStatus(Sodium.crypto_generichash_final(
                state.state, out, out.length));
    }
}
