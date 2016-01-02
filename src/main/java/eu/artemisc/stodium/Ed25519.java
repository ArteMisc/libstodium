package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Size;

import org.abstractj.kalium.Sodium;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Ed25519 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Ed25519() {}

    // constant
    public static final int SIGNBYTES = Sodium.crypto_sign_ed25519_bytes();
    public static final int PUBLICKEYBYTES = Sodium.crypto_sign_ed25519_publickeybytes();
    public static final int PRIVATEKEYBYTES = Sodium.crypto_sign_ed25519_secretkeybytes();
    public static final int SEEDBYTES = Sodium.crypto_box_seedbytes();

    // wrappers

    //
    // keypair methods
    //

    /**
     * keypair generates a new, random, keypair for use with the
     * crypto_sign_ed25519 functions.
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#key-pair-generation">libsodium docs</a>
     */
    public static void keypair(@NonNull @Size(32) final byte[] dstPublicKey,
                               @NonNull @Size(64) final byte[] dstPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Ed25519.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, PRIVATEKEYBYTES, "Ed25519.PRIVATEKEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_sign_ed25519_keypair(dstPublicKey, dstPrivateKey));
    }

    /**
     * keypairSeed generates a new keypair for use with crypto_sign_ed25519,
     * using the given seed.
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @param srcSeed
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#key-pair-generation">libsodium docs</a>
     */
    public static void keypairSeed(@NonNull @Size(32) final byte[] dstPublicKey,
                                   @NonNull @Size(64) final byte[] dstPrivateKey,
                                   @NonNull @Size(32) final byte[] srcSeed)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Ed25519.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, PRIVATEKEYBYTES, "Ed25519.PRIVATEKEYBYTES");
        Stodium.checkSize(srcSeed.length, SEEDBYTES, "Ed25519.SEEDBYTES");
        Stodium.checkStatus(Sodium.crypto_sign_ed25519_seed_keypair(dstPublicKey,
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
    public static void publicFromPrivate(@Size(32) @NonNull final byte[] dstPublicKey,
                                         @Size(64) @NonNull final byte[] srcPrivateKey)
            throws SecurityException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Ed25519.PUBLICKEYBYTES");
        Stodium.checkSize(srcPrivateKey.length, PRIVATEKEYBYTES, "Ed25519.PRIVATEKEYBYTES");
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
    public static void seedFromPrivate(@Size(32) @NonNull final byte[] dstSeed,
                                       @Size(64) @NonNull final byte[] srcPrivateKey)
            throws SecurityException {
        Stodium.checkSize(srcPrivateKey.length, PRIVATEKEYBYTES, "Ed25519.PRIVATEKEYBYTES");
        Stodium.checkSize(dstSeed.length, SEEDBYTES, "Ed25519.SEEDBYTES");
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
                           @NonNull @Size(64) final byte[] localPrivKey)
            throws SecurityException {
        Stodium.checkSize(dstSignedMsg.length, srcMsg.length + SIGNBYTES, "Ed25519.SIGNBYTES + srcMsg.length");
        Stodium.checkSize(localPrivKey.length, PRIVATEKEYBYTES, "Ed25519.PRIVATEKEYBYTES");
        final int[] dstSize = new int[1];
        Stodium.checkStatus(Sodium.crypto_sign_ed25519(dstSignedMsg, dstSize, srcMsg,
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
                           @NonNull @Size(32) final byte[] remotePubKey)
            throws SecurityException {
        Stodium.checkSize(srcSignedMsg.length, dstMsg.length + SIGNBYTES, "Ed25519.SIGNBYTES + dstMsg.length");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Ed25519.PUBLICKEYBYTES");
        final int[] dstSize = new int[1];
        Stodium.checkStatus(Sodium.crypto_sign_ed25519_open(dstMsg, dstSize,
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
     *         {@link org.abstractj.kalium.Sodium#crypto_sign_ed25519_detached(byte[], int[], byte[], int, byte[])}
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#detached-mode">libsodium docs</a>
     */
    public static int signDetached(@NonNull @Size(64) final byte[] dstSignature,
                                   @NonNull final byte[] srcMsg,
                                   @NonNull @Size(64) final byte[] localPrivKey)
            throws SecurityException {
        Stodium.checkSize(dstSignature.length, SIGNBYTES, "Ed25519.SIGNBYTES");
        Stodium.checkSize(localPrivKey.length, PRIVATEKEYBYTES, "Ed25519.PRIVATEKEYBYTES");
        final int[] dstSize = new int[1];
        Stodium.checkStatus(Sodium.crypto_sign_ed25519_detached(dstSignature, dstSize,
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
    public static boolean verifyDetached(@NonNull @Size(64) final byte[] srcSignature,
                                         @NonNull final byte[] srcMsg,
                                         @NonNull @Size(32) final byte[] remotePubKey)
            throws SecurityException {
        Stodium.checkSize(srcSignature.length, SIGNBYTES, "Ed25519.SIGNBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Ed25519.PUBLICKEYBYTES");
        return Sodium.crypto_sign_ed25519_verify_detached(srcSignature, srcMsg,
                srcMsg.length, remotePubKey) == 0;
    }
}
