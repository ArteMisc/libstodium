/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.aead;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class XChacha20Poly1305Ietf {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private XChacha20Poly1305Ietf() { throw new IllegalAccessError(); }

    // constants
    public static final int KEYBYTES  = StodiumJNI.crypto_aead_xchacha20poly1305_ietf_keybytes();
    public static final int NSECBYTES = StodiumJNI.crypto_aead_xchacha20poly1305_ietf_nsecbytes();
    public static final int NPUBBYTES = StodiumJNI.crypto_aead_xchacha20poly1305_ietf_npubbytes();
    public static final int ABYTES    = StodiumJNI.crypto_aead_xchacha20poly1305_ietf_abytes();

    // wrappers

    /**
     *
     * @param dstCipher
     * @param dstMac
     * @param srcPlain
     * @param ad
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public static void encryptDetached(final @NotNull ByteBuffer dstCipher,
                                       final @NotNull ByteBuffer dstMac,
                                       final @NotNull ByteBuffer srcPlain,
                                       final @NotNull ByteBuffer ad,
                                       final @NotNull ByteBuffer nonce,
                                       final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher, "Stodium.XChacha20Poly1305Ietf#encryptDetached(dstCipher)");
        Stodium.checkDestinationWritable(dstMac,    "Stodium.XChacha20Poly1305Ietf#encryptDetached(dstMac)");


        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining(), "XChacha20Poly1305Ietf.plain");
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES, "XChacha20Poly1305Ietf.NPUBBYTES");
        Stodium.checkSize(key.remaining(), KEYBYTES, "XChacha20Poly1305Ietf.KEYBYTES");

        Stodium.checkStatus(StodiumJNI.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(dstMac),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param ad
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public static void encrypt(final @NotNull ByteBuffer dstCipher,
                               final @NotNull ByteBuffer srcPlain,
                               final @NotNull ByteBuffer ad,
                               final @NotNull ByteBuffer nonce,
                               final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher, "Stodium.XChacha20Poly1305Ietf#encrypt(dstCipher)");

        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining() + ABYTES, "XChacha20Poly1305Ietf.plain + ABYTES");
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES, "XChacha20Poly1305Ietf.NPUBBYTES");
        Stodium.checkSize(key.remaining(), KEYBYTES, "XChacha20Poly1305Ietf.KEYBYTES");

        Stodium.checkStatus(StodiumJNI.crypto_aead_xchacha20poly1305_ietf_encrypt(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param ad
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public static void decryptDetached(final @NotNull ByteBuffer dstPlain,
                                       final @NotNull ByteBuffer srcCipher,
                                       final @NotNull ByteBuffer srcMac,
                                       final @NotNull ByteBuffer ad,
                                       final @NotNull ByteBuffer nonce,
                                       final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain, "Stodium.XChacha20Poly1305Ietf#decryptDetached(dstPlain)");

        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining(), "XChacha20Poly1305Ietf.plain");
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES, "XChacha20Poly1305Ietf.NPUBBYTES");
        Stodium.checkSize(key.remaining(), KEYBYTES, "XChacha20Poly1305Ietf.KEYBYTES");

        Stodium.checkStatus(StodiumJNI.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(srcMac),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param ad
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public static void decrypt(final @NotNull ByteBuffer dstPlain,
                               final @NotNull ByteBuffer srcCipher,
                               final @NotNull ByteBuffer ad,
                               final @NotNull ByteBuffer nonce,
                               final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain, "Stodium.XChacha20Poly1305Ietf#decrypt(dstPlain)");

        Stodium.checkSizeMin(srcCipher.remaining(), dstPlain.remaining() + ABYTES, "XChacha20Poly1305Ietf.plain + ABYTES");
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES, "XChacha20Poly1305Ietf.NPUBBYTES");
        Stodium.checkSize(key.remaining(), KEYBYTES, "XChacha20Poly1305Ietf.KEYBYTES");

        Stodium.checkStatus(StodiumJNI.crypto_aead_xchacha20poly1305_ietf_decrypt(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }
}
