/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.box;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.ReadOnlyBufferException;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.StodiumJNI;
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
    public static final int PUBLICKEYBYTES = StodiumJNI.crypto_box_publickeybytes();
    public static final int SECRETKEYBYTES = StodiumJNI.crypto_box_secretkeybytes();
    public static final int MACBYTES       = StodiumJNI.crypto_box_macbytes();
    public static final int NONCEBYTES     = StodiumJNI.crypto_box_noncebytes();
    public static final int SEEDBYTES      = StodiumJNI.crypto_box_seedbytes();
    public static final int BEFORENMBYTES  = StodiumJNI.crypto_box_beforenmbytes();
    public static final int SEALBYTES      = StodiumJNI.crypto_box_sealbytes();

    public static final String PRIMITIVE = StodiumJNI.crypto_box_primitive();

    // wrappers

    //
    // *_keypair
    //

    /**
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void keypair(final @NotNull byte[] dstPublicKey,
                               final @NotNull byte[] dstPrivateKey)
            throws StodiumException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_keypair(dstPublicKey, dstPrivateKey));
    }

    /**
     *
     * @param dstPublicKey
     * @param dstPrivateKey
     * @param srcSeed
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void seedKeypair(final @NotNull byte[] dstPublicKey,
                                   final @NotNull byte[] dstPrivateKey,
                                   final @NotNull byte[] srcSeed)
            throws StodiumException {
        Stodium.checkSize(dstPublicKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(dstPrivateKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkSize(srcSeed.length, SEEDBYTES, "Box.SEEDBYTES");
        Stodium.checkStatus(Sodium.crypto_box_seed_keypair(dstPublicKey,
                dstPrivateKey, srcSeed));
    }

    /**
     *
     * @param dstPublicKey
     * @param srcPrivateKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void publicFromPrivate(final @NotNull ByteBuffer dstPublicKey,
                                         final @NotNull ByteBuffer srcPrivateKey)
            throws StodiumException {
        Stodium.checkSize(dstPublicKey.remaining(), PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(srcPrivateKey.remaining(), SECRETKEYBYTES, "Box.SECRETKEYBYTES");
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void easy(final @NotNull byte[] dstCipher,
                            final @NotNull byte[] srcPlain,
                            final @NotNull byte[] nonce,
                            final @NotNull byte[] remotePubKey,
                            final @NotNull byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + MACBYTES, "Box.MACBYTES + srcPlain.length");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_easy(dstCipher, srcPlain,
                srcPlain.length, nonce, remotePubKey, localPrivKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void openEasy(final @NotNull byte[] dstPlain,
                                final @NotNull byte[] srcCipher,
                                final @NotNull byte[] nonce,
                                final @NotNull byte[] remotePubKey,
                                final @NotNull byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + MACBYTES, "Box.MACBYTES + dstPlain.length");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_easy(dstPlain, srcCipher,
                srcCipher.length, nonce, remotePubKey, localPrivKey));
    }

    //
    // *_detached
    //

    /**
     *
     * @param dstCipher
     * @param dstMac
     * @param srcPlain
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void detached(final @NotNull byte[] dstCipher,
                                final @NotNull byte[] dstMac,
                                final @NotNull byte[] srcPlain,
                                final @NotNull byte[] nonce,
                                final @NotNull byte[] remotePubKey,
                                final @NotNull byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length, "srcPlain.length");
        Stodium.checkSize(dstMac.length, MACBYTES, "Box.MACBYTES");
        Stodium.checkSize(nonce.length, NONCEBYTES, "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_detached(dstCipher, dstMac,
                srcPlain, srcPlain.length, nonce, remotePubKey, localPrivKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void openDetached(final @NotNull byte[] dstPlain,
                                    final @NotNull byte[] srcCipher,
                                    final @NotNull byte[] srcMac,
                                    final @NotNull byte[] nonce,
                                    final @NotNull byte[] remotePubKey,
                                    final @NotNull byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length,    dstPlain.length, "dstPlain.length");
        Stodium.checkSize(srcMac.length,       MACBYTES,        "Box.MACBYTES");
        Stodium.checkSize(nonce.length,        NONCEBYTES,      "Box.NONCEBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES,  "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES,  "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_detached(srcCipher, srcMac,
                dstPlain, srcCipher.length, nonce, remotePubKey, localPrivKey));
    }

    //
    // _beforenm
    //

    /**
     *
     * @param dstSharedKey
     * @param remotePubKey
     * @param localPrivKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void beforenm(final @NotNull byte[] dstSharedKey,
                                final @NotNull byte[] remotePubKey,
                                final @NotNull byte[] localPrivKey)
            throws StodiumException {
        Stodium.checkSize(dstSharedKey.length, BEFORENMBYTES,  "Box.BEFORENMBYTES");
        Stodium.checkSize(remotePubKey.length, PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.length, SECRETKEYBYTES, "Box.SECRETKEYBYTES");
        Stodium.checkStatus(Sodium.crypto_box_beforenm(dstSharedKey,
                remotePubKey, localPrivKey));
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
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void easyAfternm(final @NotNull byte[] dstCipher,
                                   final @NotNull byte[] srcPlain,
                                   final @NotNull byte[] nonce,
                                   final @NotNull byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length + MACBYTES, "Box.MACBYTES + srcPlain.length");
        Stodium.checkSize(nonce.length,     NONCEBYTES,    "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES, "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_easy_afternm(dstCipher, srcPlain,
                srcPlain.length, nonce, sharedKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param sharedKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void easyOpenAfternm(final @NotNull byte[] dstPlain,
                                       final @NotNull byte[] srcCipher,
                                       final @NotNull byte[] nonce,
                                       final @NotNull byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length, dstPlain.length + MACBYTES, "Box.MACBYTES + dstPlain.length");
        Stodium.checkSize(nonce.length,     NONCEBYTES,    "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES, "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_easy_afternm(dstPlain,
                srcCipher, srcCipher.length, nonce, sharedKey));
    }

    //
    // *_detached_afternm
    //

    /**
     *
     * @param srcPlain
     * @param dstCipher
     * @param dstMac
     * @param nonce
     * @param sharedKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void detachedAfternm(final @NotNull byte[] srcPlain,
                                       final @NotNull byte[] dstCipher,
                                       final @NotNull byte[] dstMac,
                                       final @NotNull byte[] nonce,
                                       final @NotNull byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(dstCipher.length, srcPlain.length, "srcPlain.length");
        Stodium.checkSize(dstMac.length,    MACBYTES,        "Box.MACBYTES");
        Stodium.checkSize(nonce.length,     NONCEBYTES,      "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES,   "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_detached_afternm(dstCipher,
                dstMac, srcPlain, srcPlain.length, nonce, sharedKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param nonce
     * @param sharedKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void openDetachedAfternm(final @NotNull byte[] dstPlain,
                                           final @NotNull byte[] srcCipher,
                                           final @NotNull byte[] srcMac,
                                           final @NotNull byte[] nonce,
                                           final @NotNull byte[] sharedKey)
            throws StodiumException {
        Stodium.checkSize(srcCipher.length, dstPlain.length, "dstPlain.length");
        Stodium.checkSize(srcMac.length,    MACBYTES,        "Box.MACBYTES");
        Stodium.checkSize(nonce.length,     NONCEBYTES,      "Box.NONCEBYTES");
        Stodium.checkSize(sharedKey.length, BEFORENMBYTES,   "Box.BEFORENMBYTES");
        Stodium.checkStatus(Sodium.crypto_box_open_detached_afternm(dstPlain,
                srcCipher, srcMac, srcCipher.length, nonce, sharedKey));
    }

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
            throws StodiumException, ReadOnlyBufferException {
        Stodium.checkDestinationWritable(dstCipher, "Stodium.Box#seal(dstCipher)");

        Stodium.checkSize(dstCipher.remaining(),    SEALBYTES + srcPlain.remaining(), "srcPlain.remaining() + Box#SEALBYTES");
        Stodium.checkSize(remotePubKey.remaining(), PUBLICKEYBYTES,                   "Box#PUBLICKEYBYTES");

        Stodium.checkStatus(
                StodiumJNI.crypto_box_seal(dstCipher, srcPlain, remotePubKey));
    }

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param localPubKey
     * @param localPrivKey
     * @return true if the sealed box was decrypted correctly, false otherwise.
     * @throws ConstraintViolationException
     * @throws StodiumException
     * @throws ReadOnlyBufferException
     *
     * @see <a href="https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html#usage">libsodium docs</a>
     */
    public static boolean sealOpen(final @NotNull ByteBuffer dstPlain,
                                   final @NotNull ByteBuffer srcCipher,
                                   final @NotNull ByteBuffer localPubKey,
                                   final @NotNull ByteBuffer localPrivKey)
            throws StodiumException, ReadOnlyBufferException {
        Stodium.checkDestinationWritable(dstPlain, "Stodium.Box#sealOpen(dstPlain)");

        Stodium.checkSize(srcCipher.remaining(),    SEALBYTES + dstPlain.remaining(), "dstPlain. + Box.SEALBYTES");
        Stodium.checkSize(localPubKey.remaining(),  PUBLICKEYBYTES, "Box.PUBLICKEYBYTES");
        Stodium.checkSize(localPrivKey.remaining(), SECRETKEYBYTES, "Box.SECRETKEYBYTES");

        return StodiumJNI.crypto_box_seal_open(
                dstPlain, srcCipher, localPubKey, localPrivKey) == 0;
    }
}
