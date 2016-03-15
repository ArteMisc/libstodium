package eu.artemisc.stodium;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import javax.crypto.AEADBadTagException;

/**
 * Chacha20Poly1305 implements the crypto_aead_chacha20poly1305* API.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Chacha20Poly1305 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Chacha20Poly1305() {}

    // constants
    public static final int KEYBYTES = Sodium.crypto_aead_chacha20poly1305_keybytes();
    public static final int NPUBBYTES = Sodium.crypto_aead_chacha20poly1305_npubbytes();
    /**
     * ABYTES is the maximum number of Additional Bytes that are added to the
     * cipher upon encryption.
     */
    public static final int ABYTES = Sodium.crypto_aead_chacha20poly1305_abytes();
    /**
     * NSECBYTES is not used by this construction.
     */
    public static final int NSECBYTES = Sodium.crypto_aead_chacha20poly1305_nsecbytes();

    // wrappers

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param ad
     * @param nonce
     * @param key
     * @return The actual number of bytes written to dstCipher
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static int encrypt(@NonNull final byte[] dstCipher,
                              @NonNull final byte[] srcPlain,
                              @NonNull final byte[] ad,
                              @NonNull final byte[] nonce,
                              @NonNull final byte[] key)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + ABYTES, "Chacha20Poly1305.ABYTES + srcPlain.length");
        Stodium.checkSize(nonce.length, NPUBBYTES, "Chacha20Poly1305.NPUBBYTES");
        Stodium.checkSize(key.length, KEYBYTES, "Chacha20Poly1305.KEYBYTES");

        final int[] size = new int[1];
        Stodium.checkStatus(Sodium.crypto_aead_chacha20poly1305_encrypt(
                dstCipher, size, srcPlain, srcPlain.length, ad, ad.length,
                null, nonce, key));
        return size[0];
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param ad
     * @param nonce
     * @param key
     * @return The actual number of bytes written to dstPlain
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static int decrypt(@NonNull final byte[] dstPlain,
                              @NonNull final byte[] srcCipher,
                              @NonNull final byte[] ad,
                              @NonNull final byte[] nonce,
                              @NonNull final byte[] key)
            throws StodiumException, AEADBadTagException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + ABYTES, "dstPlain.length + Chacha20Poly1305.ABYTES");
        Stodium.checkSize(nonce.length, NPUBBYTES, "Chacha20Poly1305.NPUBBYTES");
        Stodium.checkSize(key.length, KEYBYTES, "Chacha20Poly1305.KEYBYTES");

        final int[] size = new int[1];
        Stodium.checkStatusSealOpen(Sodium.crypto_aead_chacha20poly1305_decrypt(
                        dstPlain, size, null, srcCipher, srcCipher.length, ad, ad.length,
                        nonce, key),
                "Chacha20Poly1305#decrypt");
        return size[0];
    }
}
