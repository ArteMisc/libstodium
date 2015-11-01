package eu.artemisc.strodium.Box;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

/**
 * ox is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_box_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Box {
    // block the constructor
    private Box() {}

    // constants
    public static final int PUBLICKEYBYTES = 32;
    public static final int SECRETKEYBYTES = 32;
    public static final int MACBYTES = 16;
    public static final int NONCEBYTES = 24;
    public static final int SEEDBYTES = 32;
    public static final int BEFORENMBYTES = 32;

    //
    // validators
    //
    private static void checkBefornmLength(final int beforenmLen)
            throws SecurityException {
        if (beforenmLen != BEFORENMBYTES) {
            throw new SecurityException("Secretbox: beforenmLen != BEFORENMBYTES. " +
                    beforenmLen + " != " + BEFORENMBYTES);
        }
    }

    private static void checkKeyLengths(final int pubKeyLen,
                                        final int privKeyLen)
            throws SecurityException {
        if (pubKeyLen != PUBLICKEYBYTES) {
            throw new SecurityException("Secretbox: pubKeyLen != PUBLICKEYBYTES. " +
                    pubKeyLen + " != " + PUBLICKEYBYTES);
        }
        if (privKeyLen != SECRETKEYBYTES) {
            throw new SecurityException("Secretbox: privKeyLen != SECRETKEYBYTES. " +
                    privKeyLen + " != " + SECRETKEYBYTES);
        }
    }

    private static void checkSeedLength(final int seedLen)
            throws SecurityException {
        if (seedLen != SEEDBYTES) {
            throw new SecurityException("Secretbox: seedLen != SEEDBYTES. " +
                    seedLen + " != " + SEEDBYTES);
        }
    }

    private static void checkLengths(final int cipherLen,
                                     final int plainLen,
                                     final int nonceLen,
                                     final int pubKeyLen,
                                     final int privKeyLen)
            throws SecurityException {
        checkKeyLengths(pubKeyLen, privKeyLen);
        if (cipherLen != plainLen + MACBYTES) {
            throw new SecurityException("Secretbox: cipherLen != plainLen + MACBYTES. " +
                    cipherLen + " != " + (plainLen + MACBYTES));
        }
        if (nonceLen != NONCEBYTES) {
            throw new SecurityException("Secretbox: nonceLen != NONCEBYTES. " +
                    nonceLen + " != " + NONCEBYTES);
        }
    }

    private static void checkMacLength(final int macLen)
            throws SecurityException {
        if (macLen != MACBYTES) {
            throw new SecurityException("Secretbox: macLen != MACBYTES. " +
                    macLen + " != " + MACBYTES);
        }
    }

    private static void checkStatus(final int status)
            throws SecurityException {
        if (status == 0) {
            return;
        }
        throw new SecurityException(
                String.format("Secretbox: method returned non-zero status %d", status));
    }

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
        checkKeyLengths(dstPublicKey.length, dstPrivateKey.length);
        checkStatus(Sodium.crypto_box_keypair(dstPublicKey, dstPrivateKey));
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
        checkKeyLengths(dstPublicKey.length, dstPrivateKey.length);
        checkSeedLength(srcSeed.length);
        checkStatus(Sodium.crypto_box_seed_keypair(dstPublicKey, dstPrivateKey,
                srcSeed));
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
    public static void sealEasy(@NonNull final byte[] dstCipher,
                                @NonNull final byte[] srcPlain,
                                @NonNull final byte[] nonce,
                                @NonNull final byte[] remotePubKey,
                                @NonNull final byte[] localPrivKey)
            throws SecurityException {
        checkLengths(dstCipher.length, srcPlain.length, nonce.length,
                remotePubKey.length, localPrivKey.length);
        checkStatus(Sodium.crypto_box_easy(dstCipher, srcPlain, srcPlain.length,
                nonce, remotePubKey, localPrivKey));
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
        checkLengths(srcCipher.length, dstPlain.length, nonce.length,
                remotePubKey.length, localPrivKey.length);
        checkStatus(Sodium.crypto_box_open_easy(dstPlain, srcCipher,
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
    public static void sealDetached(@NonNull final byte[] dstCipher,
                                    @NonNull final byte[] dstMac,
                                    @NonNull final byte[] srcPlain,
                                    @NonNull final byte[] nonce,
                                    @NonNull final byte[] remotePubKey,
                                    @NonNull final byte[] localPrivKey)
            throws SecurityException {
        checkMacLength(dstMac.length);
        checkLengths(dstCipher.length, dstMac.length + srcPlain.length,
                nonce.length, remotePubKey.length, localPrivKey.length);
        checkStatus(Sodium.crypto_box_detached(dstCipher, dstMac, srcPlain,
                srcPlain.length, nonce, remotePubKey, localPrivKey));
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
        checkMacLength(srcMac.length);
        checkLengths(srcCipher.length, srcMac.length + dstPlain.length,
                nonce.length, remotePubKey.length, localPrivKey.length);
        checkStatus(Sodium.crypto_box_detached(srcCipher, srcMac, dstPlain,
                srcCipher.length, nonce, remotePubKey, localPrivKey));
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
        checkBefornmLength(dstSharedKey.length);
        checkKeyLengths(remotePubKey.length, localPrivKey.length);
        checkStatus(Sodium.crypto_box_beforenm(dstSharedKey, remotePubKey,
                localPrivKey));
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
    public static void easySealAfternm(@NonNull final byte[] dstCipher,
                                       @NonNull final byte[] srcPlain,
                                       @NonNull final byte[] nonce,
                                       @NonNull final byte[] sharedKey)
            throws SecurityException {
        checkBefornmLength(sharedKey.length);
        checkLengths(dstCipher.length, srcPlain.length, nonce.length,
                PUBLICKEYBYTES, SECRETKEYBYTES);
        checkStatus(Sodium.crypto_box_easy_afternm(dstCipher, srcPlain,
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
        checkBefornmLength(sharedKey.length);
        checkLengths(srcCipher.length, dstPlain.length, nonce.length,
                PUBLICKEYBYTES, SECRETKEYBYTES);
        checkStatus(Sodium.crypto_box_open_easy_afternm(dstPlain, srcCipher,
                srcCipher.length, nonce, sharedKey));
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
    public static void sealDetachedAfternm(@NonNull final byte[] srcPlain,
                                           @NonNull final byte[] dstCipher,
                                           @NonNull final byte[] dstMac,
                                           @NonNull final byte[] nonce,
                                           @NonNull final byte[] sharedKey)
            throws SecurityException {
        checkMacLength(dstMac.length);
        checkBefornmLength(sharedKey.length);
        checkLengths(dstCipher.length, srcPlain.length + dstMac.length,
                nonce.length, PUBLICKEYBYTES, SECRETKEYBYTES);
        checkStatus(Sodium.crypto_box_open_detached_afternm(dstCipher, dstMac,
                srcPlain, srcPlain.length, nonce, sharedKey));
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
        checkMacLength(srcMac.length);
        checkBefornmLength(sharedKey.length);
        checkLengths(srcCipher.length, dstPlain.length + srcMac.length,
                nonce.length, PUBLICKEYBYTES, SECRETKEYBYTES);
        checkStatus(Sodium.crypto_box_open_detached_afternm(dstPlain, srcCipher,
                srcMac, srcCipher.length, nonce, sharedKey));
    }
}
