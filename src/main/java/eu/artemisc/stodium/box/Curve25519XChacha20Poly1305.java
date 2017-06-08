package eu.artemisc.stodium.box;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.scalarmult.ScalarMult;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Curve25519XChacha20Poly1305
        extends Box {
    private static final @NotNull ScalarMult CURVE = ScalarMult.curve25519Instance();

    Curve25519XChacha20Poly1305() {
        super(StodiumJNI.crypto_box_curve25519xchacha20poly1305_seedbytes(),
                StodiumJNI.crypto_box_curve25519xchacha20poly1305_publickeybytes(),
                StodiumJNI.crypto_box_curve25519xchacha20poly1305_secretkeybytes(),
                StodiumJNI.crypto_box_curve25519xchacha20poly1305_beforenmbytes(),
                StodiumJNI.crypto_box_curve25519xchacha20poly1305_noncebytes(),
                StodiumJNI.crypto_box_curve25519xchacha20poly1305_macbytes(),
                StodiumJNI.crypto_box_sealbytes());
    }

    //
    // bindings
    //

    @Override
    public void seedKeypair(final @NotNull ByteBuffer dstPublic,
                            final @NotNull ByteBuffer dstPrivate,
                            final @NotNull ByteBuffer seed)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPublic);
        Stodium.checkDestinationWritable(dstPrivate);

        Stodium.checkSize(dstPrivate.remaining(), SECRETKEYBYTES);
        Stodium.checkSizeMin(dstPublic.remaining(), PUBLICKEYBYTES);
        Stodium.checkSizeMin(seed.remaining(), SEEDBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_box_curve25519xchacha20poly1305_seed_keypair(
                Stodium.ensureUsableByteBuffer(dstPublic),
                Stodium.ensureUsableByteBuffer(dstPrivate),
                Stodium.ensureUsableByteBuffer(seed)));
    }

    @Override
    public void keypair(final @NotNull ByteBuffer dstPublic,
                        final @NotNull ByteBuffer dstPrivate)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPublic);
        Stodium.checkDestinationWritable(dstPrivate);

        Stodium.checkSize(dstPrivate.remaining(), SECRETKEYBYTES);
        Stodium.checkSizeMin(dstPublic.remaining(), PUBLICKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_box_curve25519xchacha20poly1305_keypair(
                Stodium.ensureUsableByteBuffer(dstPublic),
                Stodium.ensureUsableByteBuffer(dstPrivate)));
    }

    @Override
    public void publicFromPrivate(final @NotNull ByteBuffer dstPublicKey,
                                  final @NotNull ByteBuffer srcPrivateKey)
            throws StodiumException {
        CURVE.scalarMultBase(dstPublicKey, srcPrivateKey);
    }

    @Override
    public void easy(final @NotNull ByteBuffer dstCipher,
                     final @NotNull ByteBuffer srcPlain,
                     final @NotNull ByteBuffer nonce,
                     final @NotNull ByteBuffer publicKey,
                     final @NotNull ByteBuffer privateKey)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher);

        Stodium.checkSize(privateKey.remaining(), SECRETKEYBYTES);
        Stodium.checkSize(nonce.remaining(), NONCEBYTES);
        Stodium.checkSizeMin(publicKey.remaining(), PUBLICKEYBYTES);
        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining() + MACBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_box_curve25519xchacha20poly1305_easy(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(publicKey),
                Stodium.ensureUsableByteBuffer(privateKey)));
    }

    @Override
    public boolean openEasy(final @NotNull ByteBuffer dstPlain,
                            final @NotNull ByteBuffer srcCipher,
                            final @NotNull ByteBuffer nonce,
                            final @NotNull ByteBuffer publicKey,
                            final @NotNull ByteBuffer privateKey)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSize(privateKey.remaining(), SECRETKEYBYTES);
        Stodium.checkSize(nonce.remaining(), NONCEBYTES);
        Stodium.checkSizeMin(publicKey.remaining(), PUBLICKEYBYTES);
        Stodium.checkPositive(srcCipher.remaining() - MACBYTES);
        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining() - MACBYTES);

        return 0 == StodiumJNI.crypto_box_curve25519xchacha20poly1305_open_easy(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(publicKey),
                Stodium.ensureUsableByteBuffer(privateKey));
    }

    @Override
    public void beforenm(final @NotNull ByteBuffer dstKey,
                         final @NotNull ByteBuffer srcPublic,
                         final @NotNull ByteBuffer srcPrivate)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstKey);

        Stodium.checkSize(dstKey.remaining(), BEFORENMBYTES);
        Stodium.checkSize(srcPrivate.remaining(), SECRETKEYBYTES);
        Stodium.checkSizeMin(srcPublic.remaining(), PUBLICKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_box_curve25519xchacha20poly1305_beforenm(
                Stodium.ensureUsableByteBuffer(dstKey),
                Stodium.ensureUsableByteBuffer(srcPublic),
                Stodium.ensureUsableByteBuffer(srcPrivate)));
    }

    @Override
    public void easyAfternm(final @NotNull ByteBuffer dstCipher,
                            final @NotNull ByteBuffer srcPlain,
                            final @NotNull ByteBuffer nonce,
                            final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher);

        Stodium.checkSize(key.remaining(), BEFORENMBYTES);
        Stodium.checkSize(nonce.remaining(), NONCEBYTES);
        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining() + MACBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_box_curve25519xchacha20poly1305_easy_afternm(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    @Override
    public boolean openEasyAfternm(final @NotNull ByteBuffer dstPlain,
                                   final @NotNull ByteBuffer srcCipher,
                                   final @NotNull ByteBuffer nonce,
                                   final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSize(key.remaining(), BEFORENMBYTES);
        Stodium.checkSize(nonce.remaining(), NONCEBYTES);
        Stodium.checkPositive(srcCipher.remaining() - MACBYTES);
        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining() - MACBYTES);

        return 0 == StodiumJNI.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key));
    }

    @Override
    public void seal(final @NotNull ByteBuffer dstCipher,
                     final @NotNull ByteBuffer srcPlain,
                     final @NotNull ByteBuffer remotePubKey)
            throws StodiumException {
        throw new UnsupportedOperationException("not supported yet");
    }

    @Override
    public boolean sealOpen(final @NotNull ByteBuffer dstPlain,
                            final @NotNull ByteBuffer srcCipher,
                            final @NotNull ByteBuffer localPubKey,
                            final @NotNull ByteBuffer localPrivKey)
            throws StodiumException {
        throw new UnsupportedOperationException("not supported yet");
    }
}
