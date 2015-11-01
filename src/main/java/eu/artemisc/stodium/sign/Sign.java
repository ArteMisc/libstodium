package eu.artemisc.stodium.sign;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import eu.artemisc.stodium.Stodium;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Sign {
    // Block constructor
    private Sign() {}

    // constants
    public static final int SIGNBYTES = 64;
    public static final int PUBLICKEYBYTES = 32;
    public static final int PRIVATEKEYBYTES = 64;
    public static final int SEEDBYTES = 32;

    //
    // keypair methods
    //

    public static void keypair(@NonNull final byte[] dstPublicKey,
                               @NonNull final byte[] dstPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_sign_keypair(dstPublicKey, dstPrivateKey));
    }

    public static void keypairSeed(@NonNull final byte[] dstPublicKey,
                                   @NonNull final byte[] dstPrivateKey,
                                   @NonNull final byte[] srcSeed)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        Stodium.checkSize(srcSeed.length, SEEDBYTES, "Sign.SEEDBYTES");
        Stodium.checkStatus(Sodium.crypto_sign_seed_keypair(dstPublicKey,
                dstPrivateKey, srcSeed));
    }

    //
    // conversion methods
    //

    public static void publicFromPrivate(@NonNull final byte[] dstPublicKey,
                                         @NonNull final byte[] srcPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        Stodium.checkSize(srcPrivateKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_sign_ed25519_sk_to_pk(dstPublicKey, srcPrivateKey));
    }

    public static void seedFromPrivate(@NonNull final byte[] dstSeed,
                                       @NonNull final byte[] srcPrivateKey) {
        Stodium.checkSize(srcPrivateKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        Stodium.checkSize(dstSeed.length, SEEDBYTES, "Sign.SEEDBYTES");
        Stodium.checkStatus(Sodium.crypto_sign_ed25519_sk_to_seed(dstSeed,
                srcPrivateKey));
    }

    //
    // crypto_sign*
    //

    public static int sign(@NonNull final byte[] dstSignedMsg,
                           @NonNull final byte[] srcMsg,
                           @NonNull final byte[] localPrivKey)
            throws SecurityException {
        Stodium.checkSize(dstSignedMsg.length, srcMsg.length + SIGNBYTES, "Sign.sign.SIGNBYTES + srcMsg.length");
        Stodium.checkSize(localPrivKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        // FIXME this array is supposed to mean (int*), does this work?
        int[] dstSize = new int[1];
        Stodium.checkStatus(Sodium.crypto_sign(dstSignedMsg, dstSize, srcMsg,
                srcMsg.length, localPrivKey));
        return dstSize[0];
    }

    public static int open(@NonNull final byte[] dstMsg,
                           @NonNull final byte[] srcSignedMsg,
                           @NonNull final byte[] remotePubKey)
            throws SecurityException {
        Stodium.checkSize(srcSignedMsg.length, dstMsg.length + SIGNBYTES, "Sign.sign.SIGNBYTES + dstMsg.length");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        int[] dstSize = new int[1];
        Stodium.checkStatus(Sodium.crypto_sign_open(dstMsg, dstSize,
                srcSignedMsg, srcSignedMsg.length, remotePubKey));
        return dstSize[0];
    }

    //
    // *_detached
    //

    public static int signDetached(@NonNull final byte[] dstSignature,
                                   @NonNull final byte[] srcMsg,
                                   @NonNull final byte[] localPrivKey)
            throws SecurityException {
        Stodium.checkSize(dstSignature.length, SIGNBYTES, "Sign.sign.SIGNBYTES");
        Stodium.checkSize(localPrivKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        int[] dstSize = new int[1];
        Stodium.checkStatus(Sodium.crypto_sign_detached(dstSignature, dstSize,
                srcMsg, srcMsg.length, localPrivKey));
        return dstSize[0];
    }

    public static void verifyDetached(@NonNull final byte[] srcSignature,
                                      @NonNull final byte[] srcMsg,
                                      @NonNull final byte[] remotePubKey)
            throws SecurityException {
        Stodium.checkSize(srcSignature.length, SIGNBYTES, "Sign.sign.SIGNBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_sign_verify_detached(srcSignature,
                srcMsg, srcMsg.length, remotePubKey));
    }
}
