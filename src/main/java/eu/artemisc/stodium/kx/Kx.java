package eu.artemisc.stodium.kx;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Kx {
    private static final @NotNull Singleton<Kx> X25519BLAKE = new Singleton<Kx>() {
        @NotNull
        @Override
        protected Kx initialize() {
            return new X25519Blake2b();
        }
    };

    @NotNull
    public static Kx instance() {
        return x25519Blake2b();
    }

    @NotNull
    public static Kx x25519Blake2b () {
        return X25519BLAKE.get();
    }

    // constants
    final int PUBLICKEYBYTES;
    final int SECRETKEYBYTES;
    final int SEEDBYTES;
    final int SESSIONKEYBYTES;

    Kx(final int pk,
       final int sk,
       final int seed,
       final int session) {
        PUBLICKEYBYTES  = pk;
        SECRETKEYBYTES  = sk;
        SEEDBYTES       = seed;
        SESSIONKEYBYTES = session;
    }

    /**
     *
     * @return
     */
    public final int publicKeyBytes() {
        return PUBLICKEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int secretKeyBytes() {
        return SECRETKEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int seedBytes() {
        return SEEDBYTES;
    }

    /**
     *
     * @return
     */
    public final int sessionKeyBytes() {
        return SESSIONKEYBYTES;
    }

    /**
     *
     * @param pk
     * @param sk
     * @param seed
     */
    public abstract void seedKeypair(final @NotNull ByteBuffer pk,
                                     final @NotNull ByteBuffer sk,
                                     final @NotNull ByteBuffer seed)
            throws StodiumException;

    /**
     *
     * @param pk
     * @param sk
     */
    public abstract void keypair(final @NotNull ByteBuffer pk,
                                 final @NotNull ByteBuffer sk)
            throws StodiumException;

    /**
     *
     * @param rx
     * @param tx
     * @param clientPk
     * @param clientSk
     * @param serverPk
     */
    public abstract void clientSessionKeys(final @NotNull ByteBuffer rx,
                                           final @NotNull ByteBuffer tx,
                                           final @NotNull ByteBuffer clientPk,
                                           final @NotNull ByteBuffer clientSk,
                                           final @NotNull ByteBuffer serverPk)
            throws StodiumException;

    /**
     *
     * @param rx
     * @param tx
     * @param serverPk
     * @param serverSk
     * @param clientPk
     */
    public abstract void serverSessionKeys(final @NotNull ByteBuffer rx,
                                           final @NotNull ByteBuffer tx,
                                           final @NotNull ByteBuffer serverPk,
                                           final @NotNull ByteBuffer serverSk,
                                           final @NotNull ByteBuffer clientPk)
            throws StodiumException;
}
