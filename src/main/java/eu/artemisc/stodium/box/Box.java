/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.box;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.ReadOnlyBufferException;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.scalarmult.Curve25519;

/**
 * ox is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_box_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Box {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private Box() {}

    // constants
    public static final int SEEDBYTES      = Curve25519XSalsa20Poly1305.SEEDBYTES;
    public static final int PUBLICKEYBYTES = Curve25519XSalsa20Poly1305.PUBLICKEYBYTES;
    public static final int SECRETKEYBYTES = Curve25519XSalsa20Poly1305.SECRETKEYBYTES;
    public static final int BEFORENMBYTES  = Curve25519XSalsa20Poly1305.BEFORENMBYTES;
    public static final int NONCEBYTES     = Curve25519XSalsa20Poly1305.NONCEBYTES;
    public static final int ZEROBYTES      = Curve25519XSalsa20Poly1305.ZEROBYTES;
    public static final int BOXZEROBYTES   = Curve25519XSalsa20Poly1305.BOXZEROBYTES;
    public static final int MACBYTES       = Curve25519XSalsa20Poly1305.MACBYTES;
    public static final int SEALBYTES      = StodiumJNI.crypto_box_sealbytes();

    public static final @NotNull String PRIMITIVE = StodiumJNI.crypto_box_primitive();

    // wrappers

    //
    // *_keypair
    //

    /**
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @throws StodiumException
     */
    public static void keypair(final @NotNull ByteBuffer dstPublicKey,
                               final @NotNull ByteBuffer dstPrivateKey)
            throws StodiumException {
        Curve25519XSalsa20Poly1305.keypair(dstPublicKey, dstPrivateKey);
    }

    /**
     *
     * @param dstPublic
     * @param dstPrivate
     * @param seed
     * @throws StodiumException
     */
    public static void seedKeypair(final @NotNull ByteBuffer dstPublic,
                                   final @NotNull ByteBuffer dstPrivate,
                                   final @NotNull ByteBuffer seed)
            throws StodiumException {
        Curve25519XSalsa20Poly1305.seedKeypair(dstPublic, dstPrivate, seed);
    }

    /**
     *
     * @param dstPublicKey
     * @param srcPrivateKey
     * @throws StodiumException
     */
    public static void publicFromPrivate(final @NotNull ByteBuffer dstPublicKey,
                                         final @NotNull ByteBuffer srcPrivateKey)
            throws StodiumException {
        Curve25519.x25519PrivateToPublic(dstPublicKey, srcPrivateKey);
    }

    //
    // *_easy
    //

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws StodiumException
     */
    public static void easy(final @NotNull ByteBuffer dstCipher,
                            final @NotNull ByteBuffer srcPlain,
                            final @NotNull ByteBuffer nonce,
                            final @NotNull ByteBuffer remotePubKey,
                            final @NotNull ByteBuffer localPrivKey)
            throws StodiumException {
        Curve25519XSalsa20Poly1305.easy(dstCipher, srcPlain, nonce, remotePubKey, localPrivKey);
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws StodiumException
     */
    public static void openEasy(final @NotNull ByteBuffer dstPlain,
                                final @NotNull ByteBuffer srcCipher,
                                final @NotNull ByteBuffer nonce,
                                final @NotNull ByteBuffer remotePubKey,
                                final @NotNull ByteBuffer localPrivKey)
            throws StodiumException {
        Curve25519XSalsa20Poly1305.openEasy(dstPlain, srcCipher, nonce, remotePubKey, localPrivKey);
    }

    //
    // *_detached
    // TODO
    //


    //
    // _beforenm
    //

    /**
     *
     * @param dstSharedKey
     * @param remotePubKey
     * @param localPrivKey
     * @throws StodiumException
     */
    public static void beforenm(final @NotNull ByteBuffer dstSharedKey,
                                final @NotNull ByteBuffer remotePubKey,
                                final @NotNull ByteBuffer localPrivKey)
            throws StodiumException {
        Curve25519XSalsa20Poly1305.beforenm(dstSharedKey, remotePubKey, localPrivKey);
    }

    //
    // *_easy_afternm
    //

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param sharedKey
     * @throws StodiumException
     */
    public static void easyAfternm(final @NotNull ByteBuffer dstCipher,
                                   final @NotNull ByteBuffer srcPlain,
                                   final @NotNull ByteBuffer nonce,
                                   final @NotNull ByteBuffer sharedKey)
            throws StodiumException {
        Curve25519XSalsa20Poly1305.afternm(dstCipher, srcPlain, nonce, sharedKey);
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param sharedKey
     * @throws StodiumException
     */
    public static void easyOpenAfternm(final @NotNull ByteBuffer dstPlain,
                                       final @NotNull ByteBuffer srcCipher,
                                       final @NotNull ByteBuffer nonce,
                                       final @NotNull ByteBuffer sharedKey)
            throws StodiumException {
        Curve25519XSalsa20Poly1305.openAfternm(dstPlain, srcCipher, nonce, sharedKey);
    }

    //
    // *_detached_afternm
    // TODO
    //

    //
    // _seal
    //

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param remotePubKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     * @throws ReadOnlyBufferException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html#usage">libsodium docs</a>
     */
    public static void seal(final @NotNull ByteBuffer dstCipher,
                            final @NotNull ByteBuffer srcPlain,
                            final @NotNull ByteBuffer remotePubKey)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher);

        Stodium.checkSizeMin(dstCipher.remaining(), SEALBYTES + srcPlain.remaining());
        Stodium.checkSizeMin(remotePubKey.remaining(), PUBLICKEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_box_seal(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(remotePubKey)));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param localPubKey
     * @param localPrivKey
     * @return true if the sealed box was decrypted correctly, false otherwise.
     * @throws StodiumException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html#usage">libsodium docs</a>
     */
    public static boolean sealOpen(final @NotNull ByteBuffer dstPlain,
                                   final @NotNull ByteBuffer srcCipher,
                                   final @NotNull ByteBuffer localPubKey,
                                   final @NotNull ByteBuffer localPrivKey)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSize(localPrivKey.remaining(), SECRETKEYBYTES);
        Stodium.checkSizeMin(localPubKey.remaining(), PUBLICKEYBYTES);
        Stodium.checkPositive(srcCipher.remaining() - SEALBYTES);
        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining() - SEALBYTES);

        return StodiumJNI.crypto_box_seal_open(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(localPubKey),
                Stodium.ensureUsableByteBuffer(localPrivKey)) == 0;
    }
}
