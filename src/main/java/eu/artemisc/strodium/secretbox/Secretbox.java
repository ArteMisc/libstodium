package eu.artemisc.strodium.secretbox;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

/**
 * Secretbox is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_secretbox_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Secretbox {
    public static final int KEYBYTES = 32;
    public static final int NONCEBYTES = 24;
    public static final int MACBYTES = 16;

    /**
     * checkLengths validates whether the inputlengths match the restrictions
     * created by the crypto_secretbox_* constants.
     */
    private static void checkLengths(final int cipherLen,
                                     final int plainLen,
                                     final int nonceLen,
                                     final int keyLen)
            throws SecurityException {
        if (cipherLen != plainLen + MACBYTES) {
            throw new SecurityException("Secretbox: cipherLen != plainLen + MACBYTES. " +
                    cipherLen + " != " + (plainLen + MACBYTES));
        }
        if (nonceLen != NONCEBYTES) {
            throw new SecurityException("Secretbox: nonceLen != NONCEBYTES. " +
                    nonceLen + " != " + NONCEBYTES);
        }
        if (keyLen != KEYBYTES) {
            throw new SecurityException("Secretbox: keyLen != KEYBYTES. " +
                    keyLen + " != " + KEYBYTES);
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

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param secretKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void SealEasy(@NonNull final byte[] dstCipher,
                                @NonNull final byte[] srcPlain,
                                @NonNull final byte[] nonce,
                                @NonNull final byte[] secretKey)
            throws SecurityException {
        // validate input
        checkLengths(dstCipher.length, srcPlain.length, nonce.length, secretKey.length);
        // run and check
        checkStatus(Sodium.crypto_secretbox_easy(dstCipher, srcPlain, srcPlain.length, nonce, secretKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param secretKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void OpenEasy(@NonNull final byte[] dstPlain,
                                @NonNull final byte[] srcCipher,
                                @NonNull final byte[] nonce,
                                @NonNull final byte[] secretKey)
            throws SecurityException {
        // validate input
        checkLengths(srcCipher.length, dstPlain.length, nonce.length, secretKey.length);
        // run and check
        checkStatus(Sodium.crypto_secretbox_open_easy(dstPlain, srcCipher, srcCipher.length, nonce, secretKey));

    }

    /**
     *
     * @param dstCipher
     * @param mac
     * @param srcPlain
     * @param nonce
     * @param secretKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void SealDetached(@NonNull final byte[] dstCipher,
                                    @NonNull final byte[] mac,
                                    @NonNull final byte[] srcPlain,
                                    @NonNull final byte[] nonce,
                                    @NonNull final byte[] secretKey)
            throws SecurityException {
        // validate input
        checkMacLength(mac.length);
        checkLengths(dstCipher.length + mac.length, srcPlain.length, nonce.length, secretKey.length);
        // run and check
        checkStatus(Sodium.crypto_secretbox_detached(dstCipher, mac, srcPlain, srcPlain.length, nonce, secretKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param mac
     * @param nonce
     * @param secretKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void OpenDetached(@NonNull final byte[] dstPlain,
                                    @NonNull final byte[] srcCipher,
                                    @NonNull final byte[] mac,
                                    @NonNull final byte[] nonce,
                                    @NonNull final byte[] secretKey)
            throws SecurityException {
        // validate input
        checkMacLength(mac.length);
        checkLengths(srcCipher.length + mac.length, dstPlain.length, nonce.length, secretKey.length);
        // run and check
        checkStatus(Sodium.crypto_secretbox_open_detached(dstPlain, srcCipher, mac, srcCipher.length, nonce, secretKey));
    }
}
