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
final class Aes256Gcm
        extends AEAD {
    /**
     *
     * @return true if the hardware supports the required AES instruction sets.
     */
    static boolean isAvailable() {
        return StodiumJNI.crypto_aead_aes256gcm_is_available() == 1;
    }

    Aes256Gcm() {
        super(StodiumJNI.crypto_aead_aes256gcm_keybytes(),
                StodiumJNI.crypto_aead_aes256gcm_nsecbytes(),
                StodiumJNI.crypto_aead_aes256gcm_npubbytes(),
                StodiumJNI.crypto_aead_aes256gcm_abytes());
    }

    @Override
    public void encryptDetached(final @NotNull ByteBuffer dstCipher,
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

        Stodium.checkStatus(StodiumJNI.crypto_aead_aes256gcm_encrypt_detached(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(dstMac),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    @Override
    public void encrypt(final @NotNull ByteBuffer dstCipher,
                        final @NotNull ByteBuffer srcPlain,
                        final @NotNull ByteBuffer ad,
                        final @NotNull ByteBuffer nonce,
                        final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher);

        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining() + ABYTES);
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_aead_aes256gcm_encrypt(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    @Override
    public boolean decryptDetached(final @NotNull ByteBuffer dstPlain,
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

        return StodiumJNI.NOERR == StodiumJNI.crypto_aead_aes256gcm_decrypt_detached(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(srcMac),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key));
    }

    @Override
    public boolean decrypt(final @NotNull ByteBuffer dstPlain,
                           final @NotNull ByteBuffer srcCipher,
                           final @NotNull ByteBuffer ad,
                           final @NotNull ByteBuffer nonce,
                           final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSizeMin(srcCipher.remaining(), dstPlain.remaining() + ABYTES);
        Stodium.checkSizeMin(nonce.remaining(), NPUBBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        return StodiumJNI.NOERR == StodiumJNI.crypto_aead_aes256gcm_decrypt(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(ad),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key));
    }
}
