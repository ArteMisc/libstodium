package eu.artemisc.stodium.secretbox;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import eu.artemisc.stodium.Stodium;

/**
 * Secretbox is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_secretbox_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Secretbox {
    static {
        Stodium.StrodiumInit();
    }

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
        checkLengths(dstCipher.length, srcPlain.length, nonce.length,
                secretKey.length);
        Stodium.checkStatus(Sodium.crypto_secretbox_easy(dstCipher, srcPlain,
                srcPlain.length, nonce, secretKey));
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
        checkLengths(srcCipher.length, dstPlain.length, nonce.length,
                secretKey.length);
        Stodium.checkStatus(Sodium.crypto_secretbox_open_easy(dstPlain,
                srcCipher, srcCipher.length, nonce, secretKey));
    }

    /**
     *
     * @param dstCipher
     * @param dstMac
     * @param srcPlain
     * @param nonce
     * @param secretKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void SealDetached(@NonNull final byte[] dstCipher,
                                    @NonNull final byte[] dstMac,
                                    @NonNull final byte[] srcPlain,
                                    @NonNull final byte[] nonce,
                                    @NonNull final byte[] secretKey)
            throws SecurityException {
        checkMacLength(dstMac.length);
        checkLengths(dstCipher.length + dstMac.length, srcPlain.length,
                nonce.length, secretKey.length);
        Stodium.checkStatus(Sodium.crypto_secretbox_detached(dstCipher, dstMac,
                srcPlain, srcPlain.length, nonce, secretKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param nonce
     * @param secretKey
     * @throws SecurityException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void OpenDetached(@NonNull final byte[] dstPlain,
                                    @NonNull final byte[] srcCipher,
                                    @NonNull final byte[] srcMac,
                                    @NonNull final byte[] nonce,
                                    @NonNull final byte[] secretKey)
            throws SecurityException {
        checkMacLength(srcMac.length);
        checkLengths(srcCipher.length + srcMac.length, dstPlain.length,
                nonce.length, secretKey.length);
        Stodium.checkStatus(Sodium.crypto_secretbox_open_detached(dstPlain,
                srcCipher, srcMac, srcCipher.length, nonce, secretKey));
    }
}
