/*
 * Copyright (c) 2017 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.core;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Core {

    private static final @NotNull Singleton<Core> HSALSA20 = new Singleton<Core>() {
        @NotNull
        @Override
        protected Core initialize() {
            return new HSalsa20();
        }
    };

    private static final @NotNull Singleton<Core> HCHACHA20 = new Singleton<Core>() {
        @NotNull
        @Override
        protected Core initialize() {
            return new HChacha20();
        }
    };

    @NotNull
    public static Core hsalsa20() {
        return HSALSA20.get();
    }

    @NotNull
    public static Core hchacha20() {
        return HCHACHA20.get();
    }

    // constants
    final int INPUTBYTES;
    final int OUTPUTBYTES;
    final int CONSTBYTES;
    final int KEYBYTES;

    /**
     *
     * @param input
     * @param output
     * @param constant
     * @param key
     */
    protected Core(final int input,
                   final int output,
                   final int constant,
                   final int key) {
        INPUTBYTES  = input;
        OUTPUTBYTES = output;
        CONSTBYTES  = constant;
        KEYBYTES    = key;
    }

    /**
     *
     * @return
     */
    public final int inputBytes() {
        return INPUTBYTES;
    }

    /**
     *
     * @return
     */
    public final int outputBytes() {
        return OUTPUTBYTES;
    }

    /**
     *
     * @return
     */
    public final int constBytes() {
        return CONSTBYTES;
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
     * @param dst
     * @param src
     * @param key
     * @param constant
     * @throws StodiumException
     */
    public abstract void hash(final @NotNull  ByteBuffer dst,
                              final @NotNull  ByteBuffer src,
                              final @NotNull  ByteBuffer key,
                              final @Nullable ByteBuffer constant)
            throws StodiumException;
}
