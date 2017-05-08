/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.secretbox;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import javax.crypto.AEADBadTagException;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.StodiumJNI;

/**
 * Secretbox is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_secretbox_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Secretbox {

    // block the constructor
    private Secretbox() {}

    // constants
    public static final int KEYBYTES   = Sodium.crypto_secretbox_keybytes();
    public static final int NONCEBYTES = Sodium.crypto_secretbox_noncebytes();
    public static final int MACBYTES   = Sodium.crypto_secretbox_macbytes();

    public static final @NotNull String PRIMITIVE = Sodium.crypto_secretbox_primitive();

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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void easy(final @NotNull byte[] dstCipher,
                            final @NotNull byte[] srcPlain,
                            final @NotNull byte[] nonce,
                            final @NotNull byte[] secretKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + MACBYTES);
        Stodium.checkSize(nonce.length, NONCEBYTES);
        Stodium.checkSize(secretKey.length, KEYBYTES);
        Stodium.checkStatus(Sodium.crypto_secretbox_easy(dstCipher, srcPlain,
                srcPlain.length, nonce, secretKey));
    }

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param secretKey
     * @throws StodiumException
     */
    public static void easy(final @NotNull ByteBuffer dstCipher,
                            final @NotNull ByteBuffer srcPlain,
                            final @NotNull ByteBuffer nonce,
                            final @NotNull ByteBuffer secretKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.remaining(), srcPlain.remaining() + MACBYTES);
        Stodium.checkSize(nonce.remaining(),     NONCEBYTES);
        Stodium.checkSize(secretKey.remaining(), KEYBYTES);
        Stodium.checkStatus(StodiumJNI.crypto_secretbox_easy(
                dstCipher, srcPlain, nonce, secretKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param secretKey
     * @return
     * @throws StodiumException
     */
    public static boolean openEasy(final @NotNull ByteBuffer dstPlain,
                                   final @NotNull ByteBuffer srcCipher,
                                   final @NotNull ByteBuffer nonce,
                                   final @NotNull ByteBuffer secretKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.remaining(), dstPlain.remaining() + MACBYTES);
        Stodium.checkSize(nonce.remaining(),     NONCEBYTES);
        Stodium.checkSize(secretKey.remaining(), KEYBYTES);
        return StodiumJNI.crypto_secretbox_open_easy(
                dstPlain, srcCipher, nonce, secretKey) == 0;
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param secretKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void openEasy(final @NotNull byte[] dstPlain,
                                final @NotNull byte[] srcCipher,
                                final @NotNull byte[] nonce,
                                final @NotNull byte[] secretKey)
            throws StodiumException, AEADBadTagException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + MACBYTES);
        Stodium.checkSize(nonce.length, NONCEBYTES);
        Stodium.checkSize(secretKey.length, KEYBYTES);
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void detached(final @NotNull byte[] dstCipher,
                                final @NotNull byte[] dstMac,
                                final @NotNull byte[] srcPlain,
                                final @NotNull byte[] nonce,
                                final @NotNull byte[] secretKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length);
        Stodium.checkSize(dstMac.length, MACBYTES);
        Stodium.checkSize(nonce.length, NONCEBYTES);
        Stodium.checkSize(secretKey.length, KEYBYTES);
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html">libsodium documentation</a>
     */
    public static void openDetached(final @NotNull byte[] dstPlain,
                                    final @NotNull byte[] srcCipher,
                                    final @NotNull byte[] srcMac,
                                    final @NotNull byte[] nonce,
                                    final @NotNull byte[] secretKey)
            throws StodiumException, AEADBadTagException {
        Stodium.checkSize(srcCipher.length, dstPlain.length);
        Stodium.checkSize(srcMac.length, MACBYTES);
        Stodium.checkSize(nonce.length, NONCEBYTES);
        Stodium.checkSize(secretKey.length, KEYBYTES);
        Stodium.checkStatus(Sodium.crypto_secretbox_open_detached(dstPlain,
                        srcCipher, srcMac, srcCipher.length, nonce, secretKey));
    }
}
