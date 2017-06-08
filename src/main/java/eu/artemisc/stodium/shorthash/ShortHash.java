/*
 * Copyright (c) 2017 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.shorthash;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class ShortHash {

    private static final @NotNull Singleton<ShortHash> SIPHASH24 = new Singleton<ShortHash>() {
        @NotNull
        @Override
        protected ShortHash initialize() {
            return new SipHash24();
        }
    };

    private static final @NotNull Singleton<ShortHash> SIPHASHX24 = new Singleton<ShortHash>() {
        @NotNull
        @Override
        protected ShortHash initialize() {
            return new SipHashX24();
        }
    };

    @NotNull
    public static ShortHash instance() {
        return siphash24Instance();
    }

    @NotNull
    public static ShortHash siphash24Instance() {
        return SIPHASH24.get();
    }

    @NotNull
    public static ShortHash siphashx24Instance() {
        return SIPHASHX24.get();
    }

    // constants
    final int BYTES;
    final int KEYBYTES;

    /**
     *
     * @param bytes
     * @param key
     */
    ShortHash(final int bytes,
              final int key) {
        this.BYTES    = bytes;
        this.KEYBYTES = key;
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
     * @param out
     * @param in
     * @param key
     * @throws StodiumException
     */
    public abstract void hash(final @NotNull ByteBuffer out,
                              final @NotNull ByteBuffer in,
                              final @NotNull ByteBuffer key)
            throws StodiumException;
}
