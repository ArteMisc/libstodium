package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import java.util.Arrays;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Hash {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // constants
    public static final int BYTES = Sodium.crypto_hash_bytes();

    public static final int STATE_BYTES = Sodium.crypto_hash_statebytes();

    public static final String PRIMITIVE = Sodium.crypto_generichash_primitive();

    /**
     * state holds the binary representation of the crypto_hash_state value.
     */
    @NonNull
    private final byte[] state;

    /**
     * Hash constructor creates a new hash_state. It implicitly calls
     * {@link #init()}, so calling init manually should only be required when an
     * application would wish to reuse the Hash instance.
     * @throws SecurityException
     */
    public Hash()
            throws SecurityException {
        this.state = new byte[STATE_BYTES];
        init();
    }

    /**
     * Hash copy constructor, creates a deep copy of the original Hash instance
     * by copying the internal byte array of the original state value.
     * @param original
     */
    public Hash(@NonNull final Hash original) {
        this.state = Arrays.copyOf(original.state, STATE_BYTES);
    }

    /**
     *
     * @throws SecurityException
     */
    public void init()
            throws SecurityException {
        Stodium.checkStatus(Sodium.crypto_hash_init(state));
    }

    /**
     *
     * @param in
     * @throws SecurityException
     */
    public void update(@NonNull final byte[] in)
            throws SecurityException {
        update(in, 0, in.length);
    }

    /**
     *
     * @param in
     * @param offset
     * @param len
     * @throws SecurityException
     */
    public void update(@NonNull final byte[] in,
                       final int offset,
                       final int len)
            throws SecurityException {
        Stodium.checkOffsetParams(in.length, offset, len);
        Stodium.checkStatus(Sodium.crypto_hash_update_offset(state, in, offset, len));
    }

    /**
     *
     * @param out
     * @throws SecurityException
     */
    public void doFinal(@NonNull final byte[] out)
            throws SecurityException {
        doFinal(out, 0);
    }

    /**
     *
     * @param out
     * @param offset
     * @throws SecurityException
     */
    public void doFinal(@NonNull final byte[] out,
                        final int offset)
            throws SecurityException {
        Stodium.checkOffsetParams(out.length, offset, BYTES);
        Stodium.checkStatus(Sodium.crypto_hash_final_offset(state, out, offset));
    }

    /**
     *
     * @param out
     * @param in
     * @throws SecurityException
     */
    public static void hash(@NonNull final byte[] out,
                            @NonNull final byte[] in)
            throws SecurityException {
        hash(out, 0, in, 0, in.length);
    }

    /**
     *
     * @param out
     * @param outOffset
     * @param in
     * @param inOffset
     * @param inLen
     * @throws SecurityException
     */
    public static void hash(@NonNull final byte[] out,
                            final int outOffset,
                            @NonNull final byte[] in,
                            final int inOffset,
                            final int inLen)
            throws SecurityException {
        Stodium.checkOffsetParams(out.length, outOffset, BYTES);
        Stodium.checkOffsetParams(in.length, inOffset, inLen);
        Stodium.checkStatus(Sodium.crypto_hash_offset(out, outOffset, in, inOffset, inLen));
    }
}
