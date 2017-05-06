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
public final class Chacha20Poly1305 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Chacha20Poly1305() { throw new IllegalAccessError(); }

    // constants
    public static final int KEYBYTES  = StodiumJNI.crypto_aead_chacha20poly1305_keybytes();
    public static final int NSECBYTES = StodiumJNI.crypto_aead_chacha20poly1305_nsecbytes();
    public static final int NPUBBYTES = StodiumJNI.crypto_aead_chacha20poly1305_npubbytes();
    public static final int ABYTES    = StodiumJNI.crypto_aead_chacha20poly1305_abytes();

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
        Stodium.checkDestinationWritable(dstCipher);
        Stodium.checkDestinationWritable(dstMac);


        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining());
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_aead_chacha20poly1305_encrypt_detached(
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
        Stodium.checkDestinationWritable(dstCipher);

        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining() + ABYTES);
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_aead_chacha20poly1305_encrypt(
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
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining());
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_aead_chacha20poly1305_decrypt_detached(
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
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSizeMin(srcCipher.remaining(), dstPlain.remaining() + ABYTES);
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_aead_chacha20poly1305_decrypt(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }
}
