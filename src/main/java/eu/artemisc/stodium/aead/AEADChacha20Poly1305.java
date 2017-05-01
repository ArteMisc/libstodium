/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.aead;

import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.StodiumJNI;

/**
 * AEADChacha20Poly1305 implements the crypto_aead_chacha20poly1305* API.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class AEADChacha20Poly1305 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private AEADChacha20Poly1305() {}

    // constants
    public static final int KEYBYTES  = StodiumJNI.crypto_aead_chacha20poly1305_keybytes();
    public static final int NPUBBYTES = StodiumJNI.crypto_aead_chacha20poly1305_npubbytes();
    public static final int ABYTES    = StodiumJNI.crypto_aead_chacha20poly1305_abytes();

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
    /*public static int encrypt(final @NotNull byte[] dstCipher,
                              final @NotNull byte[] srcPlain,
                              final @NotNull byte[] ad,
                              final @NotNull byte[] nonce,
                              final @NotNull byte[] key)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + ABYTES, "AEADChacha20Poly1305.ABYTES + srcPlain.length");
        Stodium.checkSize(nonce.length, NPUBBYTES, "AEADChacha20Poly1305.NPUBBYTES");
        Stodium.checkSize(key.length, KEYBYTES, "AEADChacha20Poly1305.KEYBYTES");

        final int[] size = new int[1];
        Stodium.checkStatus(StodiumJNI.crypto_aead_chacha20poly1305_encrypt(
                dstCipher, size, srcPlain, srcPlain.length, ad, ad.length,
                null, nonce, key));
        return size[0];
    }*/

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
    /*public static int decrypt(final @NotNull byte[] dstPlain,
                              final @NotNull byte[] srcCipher,
                              final @NotNull byte[] ad,
                              final @NotNull byte[] nonce,
                              final @NotNull byte[] key)
            throws StodiumException, AEADBadTagException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + ABYTES, "dstPlain.length + AEADChacha20Poly1305.ABYTES");
        Stodium.checkSize(nonce.length, NPUBBYTES, "AEADChacha20Poly1305.NPUBBYTES");
        Stodium.checkSize(key.length, KEYBYTES, "AEADChacha20Poly1305.KEYBYTES");

        final int[] size = new int[1];
        Stodium.checkStatusSealOpen(StodiumJNI.crypto_aead_chacha20poly1305_decrypt(
                        dstPlain, size, null, srcCipher, srcCipher.length, ad, ad.length,
                        nonce, key),
                "AEADChacha20Poly1305#decrypt");
        return size[0];
    }*/
}
