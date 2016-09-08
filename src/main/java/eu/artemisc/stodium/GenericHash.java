package eu.artemisc.stodium;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

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

    // constants
    public static final int BYTES        = Sodium.crypto_generichash_bytes();
    public static final int BYTES_MIN    = Sodium.crypto_generichash_bytes_min();
    public static final int BYTES_MAX    = Sodium.crypto_generichash_bytes_max();
    public static final int KEYBYTES     = Sodium.crypto_generichash_keybytes();
    public static final int KEYBYTES_MIN = Sodium.crypto_generichash_keybytes_min();
    public static final int KEYBYTES_MAX = Sodium.crypto_generichash_keybytes_max();
    public static final int STATE_BYTES  = Sodium.crypto_generichash_statebytes();

    public static final @NotNull String PRIMITIVE = Sodium.crypto_generichash_primitive();

    // Implementation of the stream API

    /**
     * state holds the binary representation of the crypto_generichash_state
     * value.
     */
    private final @NotNull byte[] state;

    /**
     * outlen is the number of output bytes the state should produce. It is
     * used byte genericHashFinal to validate that the number of
     * output-bytes read from the state is &lt;= State.outlen.
     */
    private final int outlen;


    /**
     * State allocates a byte array that holds the raw packed value of the C
     * crypto_generichash_state bytes. This constructor does NOT call
     * {@code init()}.
     *
     * @param outlen
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public GenericHash(final int outlen)
            throws StodiumException {
        Stodium.checkSize(outlen, BYTES_MIN, BYTES_MAX,
                "GenericHash.BYTES_MIN", "GenericHash.BYTES_MAX");
        this.state = new byte[STATE_BYTES];
        this.outlen = outlen;
    }

    /**
     * This constructor calls {@link #init(byte[])}.
     *
     * @param outlen
     * @param key
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public GenericHash(final           int    outlen,
                       final @Nullable byte[] key)
            throws StodiumException {
        this(outlen);
        init(key);
    }

    /**
     * State copy-constructor. If _finish should be called on multiple
     * occasions during the streaming without losing the state, it can be
     * copied.
     *
     * @param original The original State that should be copied
     */
    public GenericHash(final @NotNull GenericHash original) {
        this.state = Arrays.copyOf(original.state, original.state.length);
        this.outlen = original.outlen;
    }

    /**
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public void init()
            throws StodiumException {
        init(null);
    }

    /**
     *
     * @param key
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public void init(@Nullable final byte[] key)
            throws StodiumException {
        if (key != null) {
            Stodium.checkSize(key.length, KEYBYTES_MIN, KEYBYTES_MAX,
                    "GenericHash.KEYBYTES_MIN", "GenericHash.KEYBYTES_MAX");
        }

        Stodium.checkStatus(Sodium.crypto_generichash_init(
                state, key, key == null ? 0 : key.length, outlen));
    }

    /**
     *
     * @param in
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public void update(final @NotNull byte[] in)
            throws StodiumException {
        update(in, 0, in.length);
    }

    /**
     *
     * @param in
     * @param offset
     * @param length
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public void update(final @NotNull byte[] in,
                       final          int    offset,
                       final          int    length)
            throws StodiumException {
        Stodium.checkOffsetParams(in.length, offset, length);
            Stodium.checkStatus(Sodium.crypto_generichash_update_offset(
                    state, in, offset, length));
    }

    /**
     *
     * @param out
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public void doFinal(final @NotNull byte[] out)
            throws StodiumException {
        doFinal(out, 0, outlen);
    }

    /**
     *
     * @param out
     * @param offset
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public void doFinal(final @NotNull byte[] out,
                        final          int    offset)
            throws StodiumException {
        doFinal(out, offset, outlen);
    }

    /**
     * Can be used to truncate the output if {@code length < state.outlen}.
     *
     * @param out
     * @param offset
     * @param length
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public void doFinal(final @NotNull byte[] out,
                        final          int    offset,
                        final          int    length)
            throws StodiumException {
        Stodium.checkSize(length, 1, outlen, "1", "Blake2b.outlen");
        Stodium.checkOffsetParams(out.length, offset, outlen);
        Stodium.checkStatus(Sodium.crypto_generichash_blake2b_final_offset(
                state, out, offset, length));
    }

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
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void genericHash(final @NotNull  byte[] dstHash,
                                   final @NotNull  byte[] srcInput,
                                   final @Nullable byte[] srcKey)
            throws StodiumException {
        final GenericHash hash = new GenericHash(dstHash.length, srcKey);
        hash.update(srcInput);
        hash.doFinal(dstHash);
    }

    /**
     * genericHash without key, equivalent to calling
     * {@link #genericHash(byte[], byte[], byte[])} with {@code srcKey == null}
     * or {@code srcKey.length == 0}.
     *
     * @param dstHash the destination array the hash will be written to
     * @param srcInput the value that will be hashed
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void genericHash(final @NotNull byte[] dstHash,
                                   final @NotNull byte[] srcInput)
            throws StodiumException {
        genericHash(dstHash, srcInput, null);
    }
}
