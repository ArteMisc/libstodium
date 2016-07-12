package eu.artemisc.stodium;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;

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
    public static final int SIGNBYTES       = Sodium.crypto_sign_bytes();
    public static final int PUBLICKEYBYTES  = Sodium.crypto_sign_publickeybytes();
    public static final int PRIVATEKEYBYTES = Sodium.crypto_sign_secretkeybytes();
    public static final int SEEDBYTES       = Sodium.crypto_box_seedbytes();

    public static final String PRIMITIVE = Sodium.crypto_sign_primitive();

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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#key-pair-generation">libsodium docs</a>
     */
    public static void keypair(@NotNull final byte[] dstPublicKey,
                               @NotNull final byte[] dstPrivateKey)
            throws StodiumException {
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#key-pair-generation">libsodium docs</a>
     */
    public static void keypairSeed(@NotNull final byte[] dstPublicKey,
                                   @NotNull final byte[] dstPrivateKey,
                                   @NotNull final byte[] srcSeed)
            throws StodiumException {
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#extracting-the-seed-and-the-public-key-from-the-secret-key">libsodium docs</a>
     */
    public static void publicFromPrivate(@NotNull final byte[] dstPublicKey,
                                         @NotNull final byte[] srcPrivateKey)
            throws StodiumException {
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#extracting-the-seed-and-the-public-key-from-the-secret-key">libsodium docs</a>
     */
    public static void seedFromPrivate(@NotNull final byte[] dstSeed,
                                       @NotNull final byte[] srcPrivateKey)
            throws StodiumException {
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#combined-mode">libsodium docs</a>
     */
    public static int sign(@NotNull final byte[] dstSignedMsg,
                           @NotNull final byte[] srcMsg,
                           @NotNull final byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstSignedMsg.length, srcMsg.length + SIGNBYTES, "Sign.SIGNBYTES + srcMsg.length");
        Stodium.checkSize(localPrivKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        final int[] dstSize = new int[1];
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#combined-mode">libsodium docs</a>
     */
    public static int open(@NotNull final byte[] dstMsg,
                           @NotNull final byte[] srcSignedMsg,
                           @NotNull final byte[] remotePubKey)
            throws StodiumException {
        Stodium.checkSize(srcSignedMsg.length, dstMsg.length + SIGNBYTES, "Sign.SIGNBYTES + dstMsg.length");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        final int[] dstSize = new int[1];
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#detached-mode">libsodium docs</a>
     */
    public static int signDetached(@NotNull final byte[] dstSignature,
                                   @NotNull final byte[] srcMsg,
                                   @NotNull final byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstSignature.length, SIGNBYTES, "Sign.SIGNBYTES");
        Stodium.checkSize(localPrivKey.length, PRIVATEKEYBYTES, "Sign.PRIVATEKEYBYTES");
        final int[] dstSize = new int[1];
        Stodium.checkStatus(Sodium.crypto_sign_detached(dstSignature, dstSize,
                srcMsg, srcMsg.length, localPrivKey));
        return dstSize[0];
    }

    /**
     *
     * @param srcSignature
     * @param srcMsg
     * @param remotePubKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html#detached-mode">libsodium docs</a>
     */
    public static void verifyDetached(@NotNull final byte[] srcSignature,
                                      @NotNull final byte[] srcMsg,
                                      @NotNull final byte[] remotePubKey)
            throws StodiumException {
        Stodium.checkSize(srcSignature.length, SIGNBYTES, "Sign.SIGNBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Sign.PUBLICKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_sign_verify_detached(srcSignature,
                srcMsg, srcMsg.length, remotePubKey));
    }
}
