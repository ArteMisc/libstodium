/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.auth;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Multipart;
import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Auth {

    private static final @NotNull Singleton<Auth> HMAC_SHA_256 = new Singleton<Auth>() {
        @NotNull
        @Override
        protected Auth initialize() {
            return new HmacSha256();
        }
    };

    private static final @NotNull Singleton<Auth> HMAC_SHA_512 = new Singleton<Auth>() {
        @NotNull
        @Override
        protected Auth initialize() {
            return new HmacSha512();
        }
    };

    private static final @NotNull Singleton<Auth> HMAC_SHA_512256 = new Singleton<Auth>() {
        @NotNull
        @Override
        protected Auth initialize() {
            return new HmacSha512256();
        }
    };

    @NotNull
    public static Auth instance() {
        return HmacSha512256Instance();
    }

    @NotNull
    public static Auth HmacSha256Instance() {
        return HMAC_SHA_256.get();
    }

    @NotNull
    public static Auth HmacSha512Instance() {
        return HMAC_SHA_512.get();
    }

    @NotNull
    public static Auth HmacSha512256Instance() {
        return HMAC_SHA_512256.get();
    }

    // constants
    final int BYTES;
    final int KEYBYTES;
    final int STATEBYTES;

    /**
     *
     * @param bytes
     * @param key
     * @param state
     */
    Auth(final int bytes,
         final int key,
         final int state) {
        BYTES      = bytes;
        KEYBYTES   = key;
        STATEBYTES = state;
    }

    /**
     *
     * @return
     */
    public final int bytes() {
        return BYTES;
    }

    /**
     *
     * @return
     */
    public final int keyBytes() {
        return KEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int stateBytes() {
        return STATEBYTES;
    }

    /**
     *
     * @param dstMac
     * @param src
     * @param key
     * @throws StodiumException
     */
    public abstract void mac(final @NotNull ByteBuffer dstMac,
                             final @NotNull ByteBuffer src,
                             final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param srcMac
     * @param src
     * @param key
     * @return
     * @throws StodiumException
     */
    public abstract boolean verify(final @NotNull ByteBuffer srcMac,
                                   final @NotNull ByteBuffer src,
                                   final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param key
     * @return
     */
    @NotNull
    public abstract Multipart<Auth> init(final @NotNull ByteBuffer key)
            throws StodiumException;
}
