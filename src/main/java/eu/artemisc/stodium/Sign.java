package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import eu.artemisc.stodium.Stodium;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Sign {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Sign() {}

    // constants
    public static final int SIGNBYTES = 64;
    public static final int PUBLICKEYBYTES = 32;
    public static final int PRIVATEKEYBYTES = 64;
    public static final int SEEDBYTES = 32;

    // wrappers

    //
    // keypair methods
    //

    /**
     * keypair generates a new, random, keypair for use with the crypto_sign
     * functions. The implementation used Ed25519.
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#key-pair-generation">libsodium docs</a>
     */
    public static void keypair(@NonNull final byte[] dstPublicKey,
                               @NonNull final byte[] dstPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_sign_keypair(dstPublicKey, dstPrivateKey));
    }

    /**
     * keypairSeed generates a new keypair for use with crypto_sign, using the
     * given seed.
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @param srcSeed
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#key-pair-generation">libsodium docs</a>
     */
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

    /**
     * publicFromPrivate uses the provided private key to calculate its
     * corresponding public key.
     *
     * @param dstPublicKey
     * @param srcPrivateKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#extracting-the-seed-and-the-public-key-from-the-secret-key">libsodium docs</a>
     */
    public static void publicFromPrivate(@NonNull final byte[] dstPublicKey,
                                         @NonNull final byte[] srcPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        Stodium.checkSize(srcPrivateKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_sign_ed25519_sk_to_pk(dstPublicKey, srcPrivateKey));
    }

    /**
     * seedFromPrivate extracts the seed from the given private key.
     *
     * @param dstSeed
     * @param srcPrivateKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#extracting-the-seed-and-the-public-key-from-the-secret-key">libsodium docs</a>
     */
    public static void seedFromPrivate(@NonNull final byte[] dstSeed,
                                       @NonNull final byte[] srcPrivateKey)
            throws SecurityException {
        Stodium.checkSize(srcPrivateKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        Stodium.checkSize(dstSeed.length, SEEDBYTES, "Sign.SEEDBYTES");
        Stodium.checkStatus(Sodium.crypto_sign_ed25519_sk_to_seed(dstSeed,
                srcPrivateKey));
    }

    //
    // crypto_sign*
    //

    /**
     * sign calculates the signature for the given message, and writes the
     * result to dstSignedMsg (which includes both the message and the
     * signature). Though the signature could potentially be smaller than
     * SIGNBYTES, it is required for dstSignedMsg to be big enough to hold the
     * maximum signature size on top of the size of the original message. The
     * actual size of the signed message is returned, it is up to the called to
     * copy the result into an appropriately sized byte array.
     *
     * @param dstSignedMsg
     * @param srcMsg
     * @param localPrivKey
     * @return The actual size of the signature plus the original message.
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#combined-mode">libsodium docs</a>
     */
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

    /**
     * open verifies the signarure of a given signed message, and writes the
     * original message to dstMsg, stripped of the signature.
     *
     * dstMsg should be able to hold srcSignedMsg.length bytes as the size of
     * the signature is unknown. The real size of the unsigned message is
     * returned, and it is up to the caller to copy this result into an
     * appropriately sized byte array.
     *
     * @param dstMsg
     * @param srcSignedMsg
     * @param remotePubKey
     * @return The actual size of the original message without the signature.
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#combined-mode">libsodium docs</a>
     */
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

    /**
     *
     * @param dstSignature
     * @param srcMsg
     * @param localPrivKey
     * @return The real size of dstSignature as calculated by
     *         {@link org.abstractj.kalium.Sodium#crypto_sign_detached(byte[], int[], byte[], int, byte[])}
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#detached-mode">libsodium docs</a>
     */
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

    /**
     *
     * @param srcSignature
     * @param srcMsg
     * @param remotePubKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#detached-mode">libsodium docs</a>
     */
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
