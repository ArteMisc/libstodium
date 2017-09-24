package eu.artemisc.stodium.kx;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class X25519Blake2b
        extends Kx {
    X25519Blake2b() {
        super(StodiumJNI.crypto_kx_publickeybytes(),
                StodiumJNI.crypto_kx_secretkeybytes(),
                StodiumJNI.crypto_kx_seedbytes(),
                StodiumJNI.crypto_kx_sessionkeybytes());
    }

    @Override
    public void seedKeypair(final @NotNull ByteBuffer pk,
                            final @NotNull ByteBuffer sk,
                            final @NotNull ByteBuffer seed)
            throws StodiumException {
        Stodium.checkDestinationWritable(pk);
        Stodium.checkDestinationWritable(sk);

        Stodium.checkSize(sk.remaining(), SECRETKEYBYTES);
        Stodium.checkSizeMin(pk.remaining(), PUBLICKEYBYTES);
        Stodium.checkSizeMin(seed.remaining(), SEEDBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_kx_seed_keypair(
                Stodium.ensureUsableByteBuffer(pk),
                Stodium.ensureUsableByteBuffer(sk),
                Stodium.ensureUsableByteBuffer(seed)));
    }

    @Override
    public void keypair(final @NotNull ByteBuffer pk,
                        final @NotNull ByteBuffer sk)
            throws StodiumException {
        Stodium.checkDestinationWritable(pk);
        Stodium.checkDestinationWritable(sk);

        Stodium.checkSize(sk.remaining(), SECRETKEYBYTES);
        Stodium.checkSizeMin(pk.remaining(), PUBLICKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_kx_keypair(
                Stodium.ensureUsableByteBuffer(pk),
                Stodium.ensureUsableByteBuffer(sk)));
    }

    @Override
    public void clientSessionKeys(final @NotNull ByteBuffer rx,
                                  final @NotNull ByteBuffer tx,
                                  final @NotNull ByteBuffer clientPk,
                                  final @NotNull ByteBuffer clientSk,
                                  final @NotNull ByteBuffer serverPk)
            throws StodiumException {
        Stodium.checkDestinationWritable(rx);
        Stodium.checkDestinationWritable(tx);

        Stodium.checkSizeMin(serverPk.remaining(), PUBLICKEYBYTES);
        Stodium.checkSizeMin(clientPk.remaining(), PUBLICKEYBYTES);
        Stodium.checkSize(clientSk.remaining(), SECRETKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_kx_client_session_keys(
                Stodium.ensureUsableByteBuffer(rx),
                Stodium.ensureUsableByteBuffer(tx),
                Stodium.ensureUsableByteBuffer(clientPk),
                Stodium.ensureUsableByteBuffer(clientSk),
                Stodium.ensureUsableByteBuffer(serverPk)));
    }

    @Override
    public void serverSessionKeys(final @NotNull ByteBuffer rx,
                                  final @NotNull ByteBuffer tx,
                                  final @NotNull ByteBuffer serverPk,
                                  final @NotNull ByteBuffer serverSk,
                                  final @NotNull ByteBuffer clientPk)
            throws StodiumException {
        Stodium.checkDestinationWritable(rx);
        Stodium.checkDestinationWritable(tx);

        Stodium.checkSizeMin(clientPk.remaining(), PUBLICKEYBYTES);
        Stodium.checkSizeMin(serverPk.remaining(), PUBLICKEYBYTES);
        Stodium.checkSize(serverSk.remaining(), SECRETKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_kx_server_session_keys(
                Stodium.ensureUsableByteBuffer(rx),
                Stodium.ensureUsableByteBuffer(tx),
                Stodium.ensureUsableByteBuffer(serverPk),
                Stodium.ensureUsableByteBuffer(serverSk),
                Stodium.ensureUsableByteBuffer(clientPk)));
    }
}
