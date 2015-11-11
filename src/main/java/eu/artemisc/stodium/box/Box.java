package eu.artemisc.stodium.box;

import android.support.annotation.NonNull;
import android.support.annotation.Size;

import org.abstractj.kalium.Sodium;

import eu.artemisc.stodium.ScalarMult;
import eu.artemisc.stodium.Stodium;

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
    public static final int PUBLICKEYBYTES = 32;
    public static final int SECRETKEYBYTES = 32;
    public static final int MACBYTES = 16;
    public static final int NONCEBYTES = 24;
    public static final int SEEDBYTES = 32;
    public static final int BEFORENMBYTES = 32;

    public static final int SEALBYTES = PUBLICKEYBYTES + MACBYTES;

    // wrappers

    //
    // *_keypair
    //

    /**
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @throws SecurityException
     */
    public static void keypair(@NonNull final byte[] dstPublicKey,
                               @NonNull final byte[] dstPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_keypair(dstPublicKey, dstPrivateKey));
    }

    /**
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @param srcSeed
     * @throws SecurityException
     */
    public static void seedKeypair(@NonNull final byte[] dstPublicKey,
                                   @NonNull final byte[] dstPrivateKey,
                                   @NonNull final byte[] srcSeed)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void publicFromPrivate(@NonNull final byte[] dstPublicKey,
                                         @NonNull final byte[] srcPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(srcPrivateKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        ScalarMult.curve25519PrivateToPublic(dstPublicKey, srcPrivateKey);
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
     * @throws SecurityException
     */
    public static void easy(@NonNull final byte[] dstCipher,
                            @NonNull final byte[] srcPlain,
                            @NonNull final byte[] nonce,
                            @NonNull final byte[] remotePubKey,
                            @NonNull final byte[] localPrivKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void openEasy(@NonNull final byte[] dstPlain,
                                @NonNull final byte[] srcCipher,
                                @NonNull final byte[] nonce,
                                @NonNull final byte[] remotePubKey,
                                @NonNull final byte[] localPrivKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void detached(@NonNull final byte[] dstCipher,
                                @NonNull final byte[] dstMac,
                                @NonNull final byte[] srcPlain,
                                @NonNull final byte[] nonce,
                                @NonNull final byte[] remotePubKey,
                                @NonNull final byte[] localPrivKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void openDetached(@NonNull final byte[] dstPlain,
                                    @NonNull final byte[] srcCipher,
                                    @NonNull final byte[] srcMac,
                                    @NonNull final byte[] nonce,
                                    @NonNull final byte[] remotePubKey,
                                    @NonNull final byte[] localPrivKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void beforenm(@NonNull final byte[] dstSharedKey,
                                @NonNull final byte[] remotePubKey,
                                @NonNull final byte[] localPrivKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void easyAfternm(@NonNull final byte[] dstCipher,
                                   @NonNull final byte[] srcPlain,
                                   @NonNull final byte[] nonce,
                                   @NonNull final byte[] sharedKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void easyOpenAfternm(@NonNull final byte[] dstPlain,
                                       @NonNull final byte[] srcCipher,
                                       @NonNull final byte[] nonce,
                                       @NonNull final byte[] sharedKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void detachedAfternm(@NonNull final byte[] srcPlain,
                                       @NonNull final byte[] dstCipher,
                                       @NonNull final byte[] dstMac,
                                       @NonNull final byte[] nonce,
                                       @NonNull final byte[] sharedKey)
            throws SecurityException {
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
     * @throws SecurityException
     */
    public static void openDetachedAfternm(@NonNull final byte[] dstPlain,
                                           @NonNull final byte[] srcCipher,
                                           @NonNull final byte[] srcMac,
                                           @NonNull final byte[] nonce,
                                           @NonNull final byte[] sharedKey)
            throws SecurityException {
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
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html#usage">libsodium docs</a>
     */
    public static void seal(@NonNull final byte[] dstCipher,
                            @NonNull final byte[] srcPlain,
                            @NonNull final byte[] remotePubKey)
            throws SecurityException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + SEALBYTES, "srcPlain.length + Box.SEALBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_seal(dstCipher, srcPlain,
                srcPlain.length, remotePubKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param localPubKey
     * @param localPrivKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html#usage">libsodium docs</a>
     */
    public static void sealOpen(@NonNull final byte[] dstPlain,
                                @NonNull final byte[] srcCipher,
                                @NonNull final byte[] localPubKey,
                                @NonNull final byte[] localPrivKey)
            throws SecurityException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + SEALBYTES, "dstPlain.length + Box.SEALBYTES");
        Stodium.checkSize(localPubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_seal_open(dstPlain, srcCipher,
                srcCipher.length, localPubKey, localPrivKey));
    }
}
