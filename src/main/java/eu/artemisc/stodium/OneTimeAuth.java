package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Size;

import org.abstractj.kalium.Sodium;

import java.util.Arrays;

/**
 * OneTimeAuth wraps calls to crypto_onetimeauth, a message authentication code
 * based on Poly1305.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class OneTimeAuth {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // constants
    public static final int BYTES = Sodium.crypto_onetimeauth_bytes();
    public static final int KEYBYTES = Sodium.crypto_onetimeauth_keybytes();

    public static final int STATEBYTES = Sodium.crypto_onetimeauth_statebytes();

    public static final String PRIMITIVE = Sodium.crypto_onetimeauth_primitive();

    // Implementation of the stream API

    /**
     * state holds the binary representation of the crypto_onetimeauth_state
     * value.
     */
    @NonNull
    private final byte[] state;

    /**
     * State allocates a byte array that holds the raw packed value of the C
     * crypto_onetimeauth_state bytes.
     */
    public OneTimeAuth() {
        this.state = new byte[STATEBYTES];
    }

    /**
     * Poly1305 constructor that automatically calls {@link #init(byte[])} with
     * the provided key.
     *
     * @param key
     */
    public OneTimeAuth(@NonNull @Size(32) final byte[] key) {
        this();
        init(key);
    }

    /**
     * State copy-constructor. If _finish should be called on multiple
     * occasions during the streaming without losing the state, it can be
     * copied.
     *
     * @param original The original State that should be copied
     */
    public OneTimeAuth(@NonNull final OneTimeAuth original) {
        this.state = Arrays.copyOf(original.state, original.state.length);
    }

    /**
     *
     * @param key
     */
    public void init(@NonNull @Size(32) final byte[] key)
            throws SecurityException {
        Stodium.checkSize(key.length, KEYBYTES, "OneTimeAuth.KEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_onetimeauth_init(state, key));
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
        Stodium.checkStatus(Sodium.crypto_onetimeauth_update_offset(
                state, in, offset, length));
    }

    /**
     * equivalent to calling {@link #doFinal(byte[], int)} with
     * {@code doFinal(out, 0)}.
     *
     * @param out
     */
    public void doFinal(@NonNull @Size(min = 16) final byte[] out)
            throws SecurityException {
        doFinal(out, 0);
    }

    /**
     *
     * @param out
     * @param offset
     * @throws SecurityException
     */
    public void doFinal(@NonNull @Size(min = 16) final byte[] out,
                        final int offset)
            throws SecurityException {
        Stodium.checkOffsetParams(out.length, offset, BYTES);
        Stodium.checkStatus(Sodium.crypto_onetimeauth_final_offset(
                state, out, offset));
    }

    // wrappers

    //
    // non-stream methods
    //

    /**
     *
     * @param dstOut
     * @param srcIn
     * @param srcKey
     * @throws SecurityException
     */
    public static void auth(@NonNull @Size(min = 16) final byte[] dstOut,
                            @NonNull final byte[] srcIn,
                            @NonNull @Size(32) final byte[] srcKey)
            throws SecurityException {
        final OneTimeAuth auth = new OneTimeAuth(srcKey);
        auth.update(srcIn);
        auth.doFinal(dstOut);
    }

    /**
     *
     * @param srcTag
     * @param srcIn
     * @param srcKey
     * @return
     * @throws SecurityException
     */
    public static boolean authVerify(@NonNull @Size(min = 16) final byte[] srcTag,
                                     @NonNull final byte[] srcIn,
                                     @NonNull @Size(32) final byte[] srcKey)
            throws SecurityException {
        final byte[] verify = new byte[BYTES];
        auth(verify, srcIn, srcKey);
        return Stodium.isEqual(srcTag, verify);
    }
}
