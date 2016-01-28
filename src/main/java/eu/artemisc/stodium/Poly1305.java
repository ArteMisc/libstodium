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
    public static void auth(@NonNull final byte[] dstOut,
                            @NonNull final byte[] srcIn,
                            @NonNull final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(dstOut.length, BYTES, "Poly1305.BYTES");
        Stodium.checkSize(srcKey.length, KEYBYTES, "Poly1305.KEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_onetimeauth_poly1305(dstOut, srcIn, srcIn.length, srcKey));
    }

    /**
     *
     * @param srcTag
     * @param srcIn
     * @param srcKey
     * @return
     * @throws SecurityException
     */
    public static boolean authVerify(@NonNull final byte[] srcTag,
                                     @NonNull final byte[] srcIn,
                                     @NonNull final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(srcTag.length, BYTES, "Poly1305.BYTES");
        Stodium.checkSize(srcKey.length, KEYBYTES, "Poly1305.KEYBYTES");
        return Sodium.crypto_onetimeauth_poly1305_verify(
                srcTag, srcIn, srcIn.length, srcKey) == 0;
    }

    /**
     *
     */
    public final static class State {
        /**
         * state holds the binary representation of the
         * crypto_onetimeauth_poly1305_state value.
         */
        @NonNull
        private final byte[] state;

        /**
         * State allocates a byte array that holds the raw packed value of the C
         * crypto_onetimeauth_state bytes.
         */
        public State() {
            this.state = new byte[STATEBYTES];
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
        }

        /**
         *
         * @param key
         */
        public void init(@NonNull @Size(32) final byte[] key)
                throws SecurityException {
            authInit(this, key);
        }

        /**
         *
         * @param in
         */
        public void update(@NonNull final byte[] in)
                throws SecurityException {
            authUpdate(this, in);
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
            authUpdate(this, in, offset, length);
        }

        /**
         *
         * @param out
         */
        public void doFinal(@NonNull @Size(value = 16) final byte[] out)
                throws SecurityException {
            authFinal(this, out);
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
            final byte[] tmp = new byte[16];
            doFinal(tmp);
            System.arraycopy(tmp, 0, out, offset, 16);
        }
    }

    /**
     *
     * @param state
     * @param key
     * @throws SecurityException
     */
    public static void authInit(@NonNull final State state,
                                @NonNull final byte[] key)
            throws SecurityException {
        Stodium.checkSize(key.length, KEYBYTES, "Poly1305.KEYBYTES");
        Stodium.checkStatus(Sodium.crypto_onetimeauth_poly1305_init(state.state, key));
    }

    /**
     *
     * @param state
     * @param in
     * @throws SecurityException
     */
    public static void authUpdate(@NonNull final State state,
                                  @NonNull final byte[] in)
            throws SecurityException {
        Stodium.checkStatus(Sodium.crypto_onetimeauth_poly1305_update(
                state.state, in, in.length));
    }

    /**
     *
     * @param state
     * @param in
     * @param offset
     * @param length
     * @throws SecurityException
     */
    public static void authUpdate(@NonNull final State state,
                                  @NonNull final byte[] in,
                                  final int offset,
                                  final int length)
            throws SecurityException {
        if (offset == 0 && length == in.length) {
            authUpdate(state, in);
            return;
        }
        final byte[] cpy = new byte[length];
        System.arraycopy(in, offset, cpy, 0, length);
        authUpdate(state, cpy);
    }

    /**
     *
     * @param state
     * @param out
     */
    public static void authFinal(@NonNull final State state,
                                 @NonNull @Size(16) final byte[] out) {
        Stodium.checkSize(out.length, BYTES, "Poly1305.BYTES");
        Stodium.checkStatus(Sodium.crypto_onetimeauth_poly1305_final(state.state, out));
    }
}
