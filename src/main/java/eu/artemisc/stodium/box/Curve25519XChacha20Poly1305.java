package eu.artemisc.stodium.box;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Curve25519XChacha20Poly1305 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Curve25519XChacha20Poly1305() { throw new IllegalAccessError(); }

    // constants
    public static final int SEEDBYTES      = StodiumJNI.crypto_box_curve25519xchacha20poly1305_seedbytes();
    public static final int PUBLICKEYBYTES = StodiumJNI.crypto_box_curve25519xchachac20poly1305_publickeybytes();
    public static final int SECRETKEYBYTES = StodiumJNI.crypto_box_curve25519xchacha20poly1305_secretkeybytes();
    public static final int BEFORENMBYTES  = StodiumJNI.crypto_box_curve25519xchacha20poly1305_beforenmbytes();
    public static final int NONCEBYTES     = StodiumJNI.crypto_box_curve25519xchacha20poly1305_noncebytes();
    public static final int MACBYTES       = StodiumJNI.crypto_box_curve25519xchacha20poly1305_macbytes();

    //
    // bindings
    //

    /**
     *
     * @param dstPublic
     * @param dstPrivate
     * @param seed
     * @throws StodiumException
     */
    public static void seedKeypair(final @NotNull ByteBuffer dstPublic,
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

    /**
     *
     * @param dstPublic
     * @param dstPrivate
     * @throws StodiumException
     */
    public static void keypair(final @NotNull ByteBuffer dstPublic,
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

    /**
     *
     * @param dstKey
     * @param srcPublic
     * @param srcPrivate
     * @throws StodiumException
     */
    public static void beforenm(final @NotNull ByteBuffer dstKey,
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

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public static void afternm(final @NotNull ByteBuffer dstCipher,
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

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public static void openEasyAfternm(final @NotNull ByteBuffer dstPlain,
                                       final @NotNull ByteBuffer srcCipher,
                                       final @NotNull ByteBuffer nonce,
                                       final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSize(key.remaining(), BEFORENMBYTES);
        Stodium.checkSize(nonce.remaining(), NONCEBYTES);
        Stodium.checkPositive(srcCipher.remaining() - MACBYTES);
        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining() - MACBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param publicKey
     * @param privateKey
     */
    public static void easy(final @NotNull ByteBuffer dstCipher,
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

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param publicKey
     * @param privateKey
     * @throws StodiumException
     */
    public static void openEasy(final @NotNull ByteBuffer dstPlain,
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

        Stodium.checkStatus(StodiumJNI.crypto_box_curve25519xchacha20poly1305_open_easy(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(publicKey),
                Stodium.ensureUsableByteBuffer(privateKey)));
    }
}
