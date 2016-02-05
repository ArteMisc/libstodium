package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.Size;

import org.abstractj.kalium.Sodium;

import java.util.Arrays;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Blake2b {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // constants
    public static final int BYTES = Sodium.crypto_generichash_blake2b_bytes();
    public static final int BYTES_MIN = Sodium.crypto_generichash_blake2b_bytes_min();
    public static final int BYTES_MAX = Sodium.crypto_generichash_blake2b_bytes_max();
    public static final int KEYBYTES = Sodium.crypto_generichash_blake2b_keybytes();
    public static final int KEYBYTES_MIN = Sodium.crypto_generichash_blake2b_keybytes_min();
    public static final int KEYBYTES_MAX = Sodium.crypto_generichash_blake2b_keybytes_max();
    public static final int SALTBYTES = Sodium.crypto_generichash_blake2b_saltbytes();
    public static final int PERSONALBYTES = Sodium.crypto_generichash_blake2b_personalbytes();

    public static final int STATE_BYTES = Sodium.crypto_generichash_blake2b_statebytes();

    // Implementation of the stream API

    /**
     * state holds the binary representation of the
     * crypto_generichash_blake2b_state value.
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
     * crypto_generichash_state bytes. This constructor does NOT call
     * {@code init()}.
     */
    public Blake2b(final int outlen)
            throws SecurityException {
        Stodium.checkSize(outlen, BYTES_MIN, BYTES_MAX,
                "Blake2b.BYTES_MIN", "Blake2b.BYTES_MAX");
        this.state = new byte[STATE_BYTES];
        this.outlen = outlen;
    }

    /**
     * This constructor calls {@link #init(byte[])}.
     *
     * @param outlen
     * @param key
     * @throws SecurityException
     */
    public Blake2b(final int outlen,
                   @Nullable @Size(min = 16, max = 64) final byte[] key)
            throws SecurityException {
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
    public Blake2b(@NonNull final Blake2b original) {
        this.state = Arrays.copyOf(original.state, original.state.length);
        this.outlen = original.outlen;
    }

    /**
     *
     */
    public void init() {
        init(null);
    }

    /**
     *
     * @param key
     */
    public void init(@Nullable @Size(min = 16, max = 64) final byte[] key)
            throws SecurityException {
        if (key != null) {
            Stodium.checkSize(key.length, KEYBYTES_MIN, KEYBYTES_MAX,
                    "Blake2b.KEYBYTES_MIN", "Blake2b.KEYBYTES_MAX");
        }

        Stodium.checkStatus(Sodium.crypto_generichash_blake2b_init(
                state, key, key == null ? 0 : key.length, outlen));
    }

    /**
     *
     * @param key
     * @param salt
     * @param personal
     * @throws SecurityException
     *
     * FIXME this API should allow null-values for key (at least) and maybe for salt/personal
     */
    public void init(@NonNull @Size(min = 16, max = 64) final byte[] key,
                     @Nullable @Size(16) final byte[] salt,
                     @Nullable @Size(16) final byte[] personal)
            throws SecurityException {
        Stodium.checkSize(key.length, KEYBYTES_MIN, KEYBYTES_MAX,
                "Blake2b.KEYBYTES_MIN", "Blake2b.KEYBYTES_MAX");

        if (salt != null) {
            Stodium.checkSize(salt.length, SALTBYTES,
                    "Blake2b.SALTBYTES");
        }
        if (personal != null) {
            Stodium.checkSize(personal.length, PERSONALBYTES,
                    "Blake2b.PERSONALBYTES");
        }

        Stodium.checkStatus(
                Sodium.crypto_generichash_blake2b_init_salt_personal(
                        state, key, key.length, outlen, salt, personal));
    }

    /**
     *
     * @param in
     */
    public void update(@NonNull final byte[] in)
            throws SecurityException {
        update(in, 0, in.length);
    }

    /**
     *
     * @param in
     * @param offset
     * @param length
     * @throws SecurityException
     */
    public void update(@NonNull final byte[] in,
                       final int offset,
                       final int length)
            throws SecurityException {
        Stodium.checkOffsetParams(in.length, offset, length);
        Stodium.checkStatus(Sodium.crypto_generichash_blake2b_update_offset(
                state, in, offset, length));
    }

    /**
     *
     * @param out
     */
    public void doFinal(@NonNull @Size(min = 1, max = 64) final byte[] out)
            throws SecurityException {
        doFinal(out, 0, outlen);
    }

    /**
     *
     * @param out
     * @param offset
     * @throws SecurityException
     */
    public void doFinal(@NonNull @Size(min = 1) final byte[] out,
                        final int offset)
            throws SecurityException {
        doFinal(out, offset, outlen);
    }

    /**
     * Can be used to truncate the output if {@code length < state.outlen}.
     *
     * @param out
     * @param offset
     * @param length
     * @throws SecurityException
     */
    public void doFinal(@NonNull @Size(min = 1) final byte[] out,
                        final int offset,
                        final int length)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void genericHash(@NonNull @Size(min = 16, max = 64) final byte[] dstHash,
                                   @NonNull final byte[] srcInput,
                                   @Nullable @Size(min = 16, max = 64) final byte[] srcKey)
            throws SecurityException {
        final Blake2b blake2b = new Blake2b(dstHash.length, srcKey);
        blake2b.update(srcInput);
        blake2b.doFinal(dstHash);
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
    public static void genericHash(@NonNull @Size(min = 16, max = 64) final byte[] dstHash,
                                   @NonNull final byte[] srcInput)
            throws SecurityException {
        genericHash(dstHash, srcInput, null);
    }

    /**
     *
     * @param dstHash
     * @param srcInput
     * @param key
     * @param salt
     * @param personal
     * @throws SecurityException
     */
    public static void genericHashSaltPersonal(@NonNull @Size(min = 16, max = 64) final byte[] dstHash,
                                               @NonNull final byte[] srcInput,
                                               @NonNull @Size(min = 16, max = 64) final byte[] key,
                                               @NonNull @Size(16) final byte[] salt,
                                               @NonNull @Size(16) final byte[] personal)
            throws SecurityException {
        final Blake2b blake2b = new Blake2b(dstHash.length);
        blake2b.init(key, salt, personal);
        blake2b.update(srcInput);
        blake2b.doFinal(dstHash);
    }
}
