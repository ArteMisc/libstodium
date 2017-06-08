package eu.artemisc.stodium.sign;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class MultipartSign {

    /**
     *
     */
    public interface Spec {
        /**
         *
         * @param state
         * @param in
         * @throws StodiumException
         */
        void update(final @NotNull ByteBuffer state,
                    final @NotNull ByteBuffer in)
                throws StodiumException;

        /**
         *
         * @param state
         * @param dst
         * @throws StodiumException
         */
        void doFinal(final @NotNull ByteBuffer state,
                     final @NotNull ByteBuffer dst,
                     final @NotNull ByteBuffer priv)
                throws StodiumException;

        boolean doFinalVerify(final @NotNull ByteBuffer state,
                              final @NotNull ByteBuffer sign,
                              final @NotNull ByteBuffer priv)
                throws StodiumException;
    }

    /**
     *
     */
    private final @NotNull Spec spec;

    /**
     *
     */
    private final @NotNull ByteBuffer state;

    /**
     *
     * @param spec
     * @param state
     */
    public MultipartSign(final @NotNull Spec       spec,
                         final @NotNull ByteBuffer state) {
        this.spec  = spec;
        this.state = state;
    }

    /**
     *
     * @return
     */
    @NotNull
    public MultipartSign duplicate() {
        throw new UnsupportedOperationException();
    }

    /**
     *
     * @param src
     * @return
     * @throws StodiumException
     */
    @NotNull
    public MultipartSign update(final @NotNull ByteBuffer src)
            throws StodiumException {
        spec.update(state, src);
        return this;
    }

    /**
     *
     * @param dst
     * @param priv
     * @throws StodiumException
     */
    public void doFinal(final @NotNull ByteBuffer dst,
                        final @NotNull ByteBuffer priv)
            throws StodiumException {
        spec.doFinal(state, dst, priv);
    }

    /**
     *
     * @param sign
     * @param priv
     * @return
     * @throws StodiumException
     */
    public boolean doFinalVerify(final @NotNull ByteBuffer sign,
                                 final @NotNull ByteBuffer priv)
            throws StodiumException {
        return spec.doFinalVerify(state, sign, priv);
    }
}
