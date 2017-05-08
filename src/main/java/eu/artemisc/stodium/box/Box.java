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

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * ox is a static class that maps all calls to the corresponding native
 * implementations. All the methods are crypto_box_* functions.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Box {

    // constants
    public static final @NotNull String PRIMITIVE = StodiumJNI.crypto_box_primitive();

    private static final @NotNull Singleton<Box> CURVE_XSALSA = new Singleton<Box>() {
        @NotNull
        @Override
        protected Box initialize() {
            return new Curve25519XSalsa20Poly1305();
        }
    };

    private static final @NotNull Singleton<Box> CURVE_XCHACHA = new Singleton<Box>() {
        @NotNull
        @Override
        protected Box initialize() {
            return new Curve25519XChacha20Poly1305();
        }
    };

    @NotNull
    public static Box instance() {
        return curve25519xsalsa20poly1305Instance();
    }

    @NotNull
    public static Box curve25519xsalsa20poly1305Instance() {
        return CURVE_XSALSA.get();
    }

    @NotNull
    public static Box curve25519xchacha20poly1305Instance() {
        return CURVE_XCHACHA.get();
    }

    // constants
    final int SEEDBYTES;
    final int PUBLICKEYBYTES;
    final int SECRETKEYBYTES;
    final int BEFORENMBYTES;
    final int NONCEBYTES;
    final int MACBYTES;
    final int SEALBYTES;

    Box(final int seed,
        final int pub,
        final int secret,
        final int beforenm,
        final int nonce,
        final int mac,
        final int seal) {
        SEEDBYTES      = seed;
        PUBLICKEYBYTES = pub;
        SECRETKEYBYTES = secret;
        BEFORENMBYTES  = beforenm;
        NONCEBYTES     = nonce;
        MACBYTES       = mac;
        SEALBYTES      = seal;
    }

    /**
     *
     * @return
     */
    public final int seedBytes() {
        return SEEDBYTES;
    }

    /**
     *
     * @return
     */
    public final int publicBytes() {
        return PUBLICKEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int secretBytes() {
        return SECRETKEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int beforenmBytes() {
        return BEFORENMBYTES;
    }

    /**
     *
     * @return
     */
    public final int nonceBytes() {
        return NONCEBYTES;
    }

    /**
     *
     * @return
     */
    public final int macBytes() {
        return MACBYTES;
    }

    /**
     *
     * @return
     */
    public final int sealBytes() {
        return SEALBYTES;
    }

    //
    // *_keypair
    //

    /**
     *
     * @param dstPublic
     * @param dstPrivate
     * @throws StodiumException
     */
    public abstract void keypair(final @NotNull ByteBuffer dstPublic,
                                 final @NotNull ByteBuffer dstPrivate)
            throws StodiumException;

    /**
     *
     * @param dstPublic
     * @param dstPrivate
     * @param seed
     * @throws StodiumException
     */
    public abstract void seedKeypair(final @NotNull ByteBuffer dstPublic,
                                     final @NotNull ByteBuffer dstPrivate,
                                     final @NotNull ByteBuffer seed)
            throws StodiumException;

    /**
     *
     * @param dstPublic
     * @param srcPrivate
     * @throws StodiumException
     */
    public abstract void publicFromPrivate(final @NotNull ByteBuffer dstPublic,
                                           final @NotNull ByteBuffer srcPrivate)
            throws StodiumException;

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
    public abstract void easy(final @NotNull ByteBuffer dstCipher,
                              final @NotNull ByteBuffer srcPlain,
                              final @NotNull ByteBuffer nonce,
                              final @NotNull ByteBuffer remotePubKey,
                              final @NotNull ByteBuffer localPrivKey)
            throws StodiumException;

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param remotePubKey
     * @param localPrivKey
     * @return
     * @throws StodiumException
     */
    public abstract boolean openEasy(final @NotNull ByteBuffer dstPlain,
                                     final @NotNull ByteBuffer srcCipher,
                                     final @NotNull ByteBuffer nonce,
                                     final @NotNull ByteBuffer remotePubKey,
                                     final @NotNull ByteBuffer localPrivKey)
            throws StodiumException;

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
    public abstract void beforenm(final @NotNull ByteBuffer dstSharedKey,
                                  final @NotNull ByteBuffer remotePubKey,
                                  final @NotNull ByteBuffer localPrivKey)
            throws StodiumException;

    //
    // *_easy_afternm
    //

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public abstract void easyAfternm(final @NotNull ByteBuffer dstCipher,
                                     final @NotNull ByteBuffer srcPlain,
                                     final @NotNull ByteBuffer nonce,
                                     final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param key
     * @return
     * @throws StodiumException
     */
    public abstract boolean openEasyAfternm(final @NotNull ByteBuffer dstPlain,
                                            final @NotNull ByteBuffer srcCipher,
                                            final @NotNull ByteBuffer nonce,
                                            final @NotNull ByteBuffer key)
            throws StodiumException;

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
     * @throws StodiumException
     */
    public abstract void seal(final @NotNull ByteBuffer dstCipher,
                              final @NotNull ByteBuffer srcPlain,
                              final @NotNull ByteBuffer remotePubKey)
            throws StodiumException;

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param localPubKey
     * @param localPrivKey
     * @return true if the sealed box was decrypted correctly, false otherwise.
     * @throws StodiumException
     */
    public abstract boolean sealOpen(final @NotNull ByteBuffer dstPlain,
                                     final @NotNull ByteBuffer srcCipher,
                                     final @NotNull ByteBuffer localPubKey,
                                     final @NotNull ByteBuffer localPrivKey)
            throws StodiumException;
}
