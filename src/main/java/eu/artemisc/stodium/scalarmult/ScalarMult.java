package eu.artemisc.stodium.scalarmult;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class ScalarMult {

    private static final @NotNull Singleton<ScalarMult> CURVE25519 = new Singleton<ScalarMult>() {
        @NotNull
        @Override
        protected ScalarMult initialize() {
            return new Curve25519();
        }
    };

    @NotNull
    public static ScalarMult instance() {
        return curve25519Instance();
    }

    @NotNull
    public static ScalarMult curve25519Instance() {
        return CURVE25519.get();
    }

    // constants
    final int BYTES;
    final int SCALARBYTES;

    /**
     *
     * @param bytes
     * @param scalar
     */
    ScalarMult(final int bytes,
               final int scalar) {
        this.BYTES       = bytes;
        this.SCALARBYTES = scalar;
    }

    /**
     *
     * @return
     */
    public final int bytes() {
        return BYTES;
    }

    /**
     *
     * @return
     */
    public final int scalarBytes() {
        return SCALARBYTES;
    }

    /**
     *
     * @param dst
     * @param src
     * @param groupElement
     * @throws StodiumException
     */
    public abstract void scalarMult(final @NotNull ByteBuffer dst,
                                    final @NotNull ByteBuffer src,
                                    final @NotNull ByteBuffer groupElement)
            throws StodiumException;

    /**
     *
     * @param dst
     * @param src
     * @throws StodiumException
     */
    public abstract void scalarMultBase(final @NotNull ByteBuffer dst,
                                        final @NotNull ByteBuffer src)
            throws StodiumException;
}