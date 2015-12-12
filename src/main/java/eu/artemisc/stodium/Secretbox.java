package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Size;
import android.util.Log;

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
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Secretbox() {}

    // constants
    public static final int KEYBYTES = 32;
    public static final int NONCEBYTES = 24;
    public static final int MACBYTES = 16;

    // wrappers

    //
    // _easy
    //

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
    public static void easy(@NonNull final byte[] dstCipher,
                            @NonNull final byte[] srcPlain,
                            @NonNull final byte[] nonce,
                            @NonNull final byte[] secretKey)
            throws SecurityException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + MACBYTES, "srcPlain.length + Secretbox.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Secretbox.NONCEBYTES");
        Stodium.checkSize(secretKey.length, KEYBYTES, "Secretbox.KEYBYTES");
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
    public static void openEasy(@NonNull final byte[] dstPlain,
                                @NonNull final byte[] srcCipher,
                                @NonNull final byte[] nonce,
                                @NonNull final byte[] secretKey)
            throws SecurityException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + MACBYTES, "dstPlain.length + Secretbox.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Secretbox.NONCEBYTES");
        Stodium.checkSize(secretKey.length, KEYBYTES, "Secretbox.KEYBYTES");
        Stodium.checkStatus(Sodium.crypto_secretbox_open_easy(dstPlain,
                srcCipher, srcCipher.length, nonce, secretKey));
    }

    //
    // _detached
    //

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
    public static void detached(@NonNull final byte[] dstCipher,
                                @NonNull final byte[] dstMac,
                                @NonNull final byte[] srcPlain,
                                @NonNull final byte[] nonce,
                                @NonNull final byte[] secretKey)
            throws SecurityException {
        Stodium.checkSize(dstCipher.length, srcPlain.length, "srcPlain.length");
        Stodium.checkSize(dstMac.length, MACBYTES, "Secretbox.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Secretbox.NONCEBYTES");
        Stodium.checkSize(secretKey.length, KEYBYTES, "Secretbox.KEYBYTES");
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
    public static void openDetached(@NonNull final byte[] dstPlain,
                                    @NonNull final byte[] srcCipher,
                                    @NonNull final byte[] srcMac,
                                    @NonNull final byte[] nonce,
                                    @NonNull final byte[] secretKey)
            throws SecurityException {
        Stodium.checkSize(srcCipher.length, dstPlain.length, "dstPlain.length");
        Stodium.checkSize(srcMac.length, MACBYTES, "Secretbox.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Secretbox.NONCEBYTES");
        Stodium.checkSize(secretKey.length, KEYBYTES, "Secretbox.KEYBYTES");
        Stodium.checkStatus(Sodium.crypto_secretbox_open_detached(dstPlain,
                srcCipher, srcMac, srcCipher.length, nonce, secretKey));
    }
}
