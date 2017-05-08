package eu.artemisc.stodium;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Multipart<T> {

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
                     final @NotNull ByteBuffer dst)
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
    public Multipart(final @NotNull Spec       spec,
                     final @NotNull ByteBuffer state) {
        this.spec  = spec;
        this.state = state;
    }

    /**
     *
     * @return
     */
    @NotNull
    public Multipart<T> duplicate() {
        throw new UnsupportedOperationException();
    }

    /**
     *
     * @param src
     * @return
     * @throws StodiumException
     */
    @NotNull
    public Multipart<?> update(final @NotNull ByteBuffer src)
            throws StodiumException {
        spec.update(state, src);
        return this;
    }

    /**
     *
     * @param dst
     * @throws StodiumException
     */
    public void doFinal(final @NotNull ByteBuffer dst)
            throws StodiumException {
        spec.doFinal(state, dst);
    }

    /**
     *
     * @param cmp
     * @return
     */
    public boolean verifyFinal(final @NotNull ByteBuffer cmp)
            throws StodiumException {
        final ByteBuffer tmp;
        tmp = ByteBuffer.allocateDirect(cmp.remaining());
        doFinal(tmp);
        return Stodium.isEqual(tmp, cmp);
    }
}
