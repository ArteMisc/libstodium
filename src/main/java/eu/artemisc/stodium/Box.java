package eu.artemisc.stodium;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

/**
 * ox is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_box_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Box {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Box() {}

    // constants
    public static final int PUBLICKEYBYTES = StodiumJNI.crypto_box_publickeybytes();
    public static final int SECRETKEYBYTES = StodiumJNI.crypto_box_secretkeybytes();
    public static final int MACBYTES       = StodiumJNI.crypto_box_macbytes();
    public static final int NONCEBYTES     = StodiumJNI.crypto_box_noncebytes();
    public static final int SEEDBYTES      = StodiumJNI.crypto_box_seedbytes();
    public static final int BEFORENMBYTES  = StodiumJNI.crypto_box_beforenmbytes();
    public static final int SEALBYTES      = StodiumJNI.crypto_box_sealbytes();

    public static final String PRIMITIVE = StodiumJNI.crypto_box_primitive();

    // wrappers

    //
    // *_keypair
    //

    /**
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void keypair(@NotNull final byte[] dstPublicKey,
                               @NotNull final byte[] dstPrivateKey)
            throws StodiumException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_keypair(dstPublicKey, dstPrivateKey));
    }

    /**
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @param srcSeed
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void seedKeypair(@NotNull final byte[] dstPublicKey,
                                   @NotNull final byte[] dstPrivateKey,
                                   @NotNull final byte[] srcSeed)
            throws StodiumException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkSize(srcSeed.length, SEEDBYTES, "Box.SEEDBYTES");
        Stodium.checkStatus(Sodium.crypto_box_seed_keypair(dstPublicKey,
                dstPrivateKey, srcSeed));
    }

    /**
     *
     * @param dstPublicKey
     * @param srcPrivateKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void publicFromPrivate(@NotNull final ByteBuffer dstPublicKey,
                                         @NotNull final ByteBuffer srcPrivateKey)
            throws StodiumException {
        Stodium.checkSize(dstPublicKey.remaining(), PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(srcPrivateKey.remaining(), SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Curve25519.x25519PrivateToPublic(dstPublicKey, srcPrivateKey);
    }

    //
    // *_easy
    //

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void easy(@NotNull final byte[] dstCipher,
                            @NotNull final byte[] srcPlain,
                            @NotNull final byte[] nonce,
                            @NotNull final byte[] remotePubKey,
                            @NotNull final byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + MACBYTES, "Box.MACBYTES + srcPlain.length");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_easy(dstCipher, srcPlain,
                srcPlain.length, nonce, remotePubKey, localPrivKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void openEasy(@NotNull final byte[] dstPlain,
                                @NotNull final byte[] srcCipher,
                                @NotNull final byte[] nonce,
                                @NotNull final byte[] remotePubKey,
                                @NotNull final byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + MACBYTES, "Box.MACBYTES + dstPlain.length");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_easy(dstPlain, srcCipher,
                srcCipher.length, nonce, remotePubKey, localPrivKey));
    }

    //
    // *_detached
    //

    /**
     *
     * @param dstCipher
     * @param dstMac
     * @param srcPlain
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void detached(@NotNull final byte[] dstCipher,
                                @NotNull final byte[] dstMac,
                                @NotNull final byte[] srcPlain,
                                @NotNull final byte[] nonce,
                                @NotNull final byte[] remotePubKey,
                                @NotNull final byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length, "srcPlain.length");
        Stodium.checkSize(dstMac.length, MACBYTES, "Box.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_detached(dstCipher, dstMac,
                srcPlain, srcPlain.length, nonce, remotePubKey, localPrivKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void openDetached(@NotNull final byte[] dstPlain,
                                    @NotNull final byte[] srcCipher,
                                    @NotNull final byte[] srcMac,
                                    @NotNull final byte[] nonce,
                                    @NotNull final byte[] remotePubKey,
                                    @NotNull final byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length, dstPlain.length, "dstPlain.length");
        Stodium.checkSize(srcMac.length, MACBYTES, "Box.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_detached(srcCipher, srcMac,
                dstPlain, srcCipher.length, nonce, remotePubKey, localPrivKey));
    }

    //
    // _beforenm
    //

    /**
     *
     * @param dstSharedKey
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void beforenm(@NotNull final byte[] dstSharedKey,
                                @NotNull final byte[] remotePubKey,
                                @NotNull final byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstSharedKey.length, BEFORENMBYTES, "Box.BEFORENMBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_beforenm(dstSharedKey,
                remotePubKey, localPrivKey));
    }

    //
    // *_easy_afternm
    //

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param sharedKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void easyAfternm(@NotNull final byte[] dstCipher,
                                   @NotNull final byte[] srcPlain,
                                   @NotNull final byte[] nonce,
                                   @NotNull final byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + MACBYTES, "Box.MACBYTES + srcPlain.length");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES, "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_easy_afternm(dstCipher, srcPlain,
                srcPlain.length, nonce, sharedKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param sharedKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void easyOpenAfternm(@NotNull final byte[] dstPlain,
                                       @NotNull final byte[] srcCipher,
                                       @NotNull final byte[] nonce,
                                       @NotNull final byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + MACBYTES, "Box.MACBYTES + dstPlain.length");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES, "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_easy_afternm(dstPlain,
                srcCipher, srcCipher.length, nonce, sharedKey));
    }

    //
    // *_detached_afternm
    //

    /**
     *
     * @param srcPlain
     * @param dstCipher
     * @param dstMac
     * @param nonce
     * @param sharedKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void detachedAfternm(@NotNull final byte[] srcPlain,
                                       @NotNull final byte[] dstCipher,
                                       @NotNull final byte[] dstMac,
                                       @NotNull final byte[] nonce,
                                       @NotNull final byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length, "srcPlain.length");
        Stodium.checkSize(dstMac.length, MACBYTES, "Box.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES, "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_detached_afternm(dstCipher,
                dstMac, srcPlain, srcPlain.length, nonce, sharedKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param nonce
     * @param sharedKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void openDetachedAfternm(@NotNull final byte[] dstPlain,
                                           @NotNull final byte[] srcCipher,
                                           @NotNull final byte[] srcMac,
                                           @NotNull final byte[] nonce,
                                           @NotNull final byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length, dstPlain.length, "dstPlain.length");
        Stodium.checkSize(srcMac.length, MACBYTES, "Box.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES, "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_detached_afternm(dstPlain,
                srcCipher, srcMac, srcCipher.length, nonce, sharedKey));
    }

    //
    // _seal
    //

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param remotePubKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     * @throws ReadOnlyBufferException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html#usage">libsodium docs</a>
     */
    public static void seal(@NotNull final ByteBuffer dstCipher,
                            @NotNull final ByteBuffer srcPlain,
                            @NotNull final ByteBuffer remotePubKey)
            throws StodiumException, ReadOnlyBufferException {
        Stodium.checkDestinationWritable(dstCipher, "Stodium.Box#seal(dstCipher)");

        Stodium.checkSize(dstCipher.remaining(),    SEALBYTES + srcPlain.remaining(), "srcPlain.remaining() + Box#SEALBYTES");
        Stodium.checkSize(remotePubKey.remaining(), PUBLICKEYBYTES,                   "Box#PUBLICKEYBYTES");

        Stodium.checkStatus(
                StodiumJNI.crypto_box_seal(dstCipher, srcPlain, remotePubKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param localPubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     * @throws ReadOnlyBufferException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html#usage">libsodium docs</a>
     */
    public static void sealOpen(@NotNull final ByteBuffer dstPlain,
                                @NotNull final ByteBuffer srcCipher,
                                @NotNull final ByteBuffer localPubKey,
                                @NotNull final ByteBuffer localPrivKey)
            throws StodiumException, ReadOnlyBufferException {
        Stodium.checkDestinationWritable(dstPlain, "Stodium.Box#sealOpen(dstPlain)");

        Stodium.checkSize(srcCipher.remaining(),    SEALBYTES + dstPlain.remaining(), "dstPlain. + Box.SEALBYTES");
        Stodium.checkSize(localPubKey.remaining(),  PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.remaining(), SECRETKEYBYTES, "Box.SECRETKEYBYTES");

        Stodium.checkStatus(StodiumJNI.crypto_box_seal_open(
                dstPlain, srcCipher, localPubKey, localPrivKey));
    }
}
