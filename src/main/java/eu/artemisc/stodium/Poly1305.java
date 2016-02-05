package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.Size;

import org.abstractj.kalium.Sodium;

import java.util.Arrays;

/**
 * Poly1305 wraps the crypto_onetimeauth_poly1305 methods.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Poly1305 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // constants
    public static final int BYTES = Sodium.crypto_onetimeauth_poly1305_bytes();
    public static final int KEYBYTES = Sodium.crypto_onetimeauth_poly1305_keybytes();

    public static final int STATEBYTES = Sodium.crypto_onetimeauth_poly1305_statebytes();

    // Implementation of the stream API

    /**
     * state holds the binary representation of the
     * crypto_onetimeauth_poly1305_state value.
     */
    @NonNull
    private final byte[] state;

    /**
     * State allocates a byte array that holds the raw packed value of the C
     * crypto_onetimeauth_poly1305_state bytes.
     */
    public Poly1305() {
        this.state = new byte[STATEBYTES];
    }

    /**
     * Poly1305 constructor that automatically calls {@link #init(byte[])} with
     * the provided key.
     *
     * @param key
     */
    public Poly1305(@NonNull @Size(32) final byte[] key) {
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
    public Poly1305(@NonNull final Poly1305 original) {
        this.state = Arrays.copyOf(original.state, original.state.length);
    }

    /**
     *
     * @param key
     */
    public void init(@NonNull @Size(32) final byte[] key)
            throws SecurityException {
        Stodium.checkSize(key.length, KEYBYTES, "Poly1305.KEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_onetimeauth_poly1305_init(state, key));
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
        Stodium.checkStatus(Sodium.crypto_onetimeauth_poly1305_update_offset(
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
        Stodium.checkStatus(Sodium.crypto_onetimeauth_poly1305_final_offset(
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
        final Poly1305 poly1305 = new Poly1305(srcKey);
        poly1305.update(srcIn);
        poly1305.doFinal(dstOut);
    }

    /**
     *
     * @param srcTag
     * @param srcIn
     * @param srcKey
     * @return
     * @throws SecurityException
     */
    public static boolean authVerify(@NonNull @Size(16) final byte[] srcTag,
                                     @NonNull final byte[] srcIn,
                                     @NonNull @Size(32) final byte[] srcKey)
            throws SecurityException {
        final byte[] verify = new byte[BYTES];
        auth(verify, srcIn, srcKey);
        return Stodium.isEqual(srcTag, verify);
    }
}
