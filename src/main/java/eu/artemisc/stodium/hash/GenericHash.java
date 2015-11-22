package eu.artemisc.stodium.hash;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import org.abstractj.kalium.Sodium;
import org.abstractj.kalium.crypto_generichash_state;

import eu.artemisc.stodium.Stodium;

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
    public static final int BYTES = 32;
    public static final int BYTES_MIN = 16;
    public static final int BYTES_MAX = 64;
    public static final int KEYBYTES = 32;
    public static final int KEYBYTES_MIN = 16;
    public static final int KEYBYTES_MAX = 64;

    public static final int SALTBYTES = 16;
    public static final int PERSONALBYTES = 16;

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

    // TODO TODO TODO TODO TODO
    // WARNING This code is experimental and potentially dangerous to use

    public final static class State {
        @NonNull
        private final crypto_generichash_state state;
        private int outlen;

        public State() {
            state = new crypto_generichash_state();
            outlen = 0;
        }

        @NonNull
        public static State getNewInstance() {
            return new State();
        }
    }

    public static void genericHashInit(@NonNull final State state,
                                       @NonNull final byte[] key,
                                       final int outlen)
            throws SecurityException {
        Stodium.checkSize(key.length, KEYBYTES_MIN, KEYBYTES_MAX,
                "GenericHash.KEYBYTES_MIN", "GenericHash.KEYBYTES_MAX");
        Stodium.checkSize(outlen, BYTES_MIN, BYTES_MAX,
                "GenericHash.BYTES_MIN", "GenericHash.BYTES_MAX");
        Stodium.checkStatus(Sodium.crypto_generichash_init(state.state,
                key, key.length, outlen));
        state.outlen = outlen;
    }

    public static void genericHashUpdate(@NonNull final State state,
                                         @NonNull final byte[] in)
            throws SecurityException {
        Stodium.checkStatus(Sodium.crypto_generichash_update(
                state.state, in, in.length));
    }

    public static void genericHashFinal(@NonNull final State state,
                                        @NonNull final byte[] out)
            throws SecurityException {
        Stodium.checkSize(out.length, 0, state.outlen, "0", "outlen");
        Stodium.checkStatus(Sodium.crypto_generichash_final(
                state.state, out, out.length));
    }
}
