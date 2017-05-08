/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.hash;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Multipart;
import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Hash {

    private static final @NotNull Singleton<Hash> SHA_256 = new Singleton<Hash>() {
        @NotNull
        @Override
        protected Hash initialize() {
            return new Sha256();
        }
    };

    private static final @NotNull Singleton<Hash> SHA_512 = new Singleton<Hash>() {
        @NotNull
        @Override
        protected Hash initialize() {
            return new Sha512();
        }
    };

    @NotNull
    public static Hash instance() {
        return Sha512Instance();
    }

    @NotNull
    public static Hash Sha256Instance() {
        return SHA_256.get();
    }

    @NotNull
    public static Hash Sha512Instance() {
        return SHA_512.get();
    }

    // constants
    final int BYTES;
    final int STATEBYTES;

    /**
     *
     * @param bytes
     * @param state
     */
    protected Hash(final int bytes,
                   final int state) {
        BYTES      = bytes;
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
    public final int stateBytes() {
        return STATEBYTES;
    }

    /**
     *
     * @param dstHash
     * @param src
     * @throws StodiumException
     */
    public abstract void hash(final @NotNull ByteBuffer dstHash,
                              final @NotNull ByteBuffer src)
            throws StodiumException;

    /**
     *
     * @return
     */
    @NotNull
    public abstract Multipart<Hash> init()
            throws StodiumException;
}
