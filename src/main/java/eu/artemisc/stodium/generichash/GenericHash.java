/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.generichash;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Multipart;
import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.hash.Hash;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class GenericHash
        extends Hash {

    private static final @NotNull Singleton<GenericHash> BLAKE2B = new Singleton<GenericHash>() {
        @NotNull
        @Override
        protected GenericHash initialize() {
            return new Blake();
        }
    };


    @NotNull
    public static GenericHash instance() {
        return blake2bInstance();
    }

    @NotNull
    public static GenericHash blake2bInstance() {
        return BLAKE2B.get();
    }

    // constants
    final int KEYBYTES;
    final int KEYBYTES_MIN;
    final int KEYBYTES_MAX;
    final int BYTES_MIN;
    final int BYTES_MAX;

    /**
     *
     * @param bytes
     * @param bytesMin
     * @param bytesMax
     * @param key
     * @param keyMin
     * @param keyMax
     * @param state
     */
    protected GenericHash(final int bytes,
                          final int bytesMin,
                          final int bytesMax,
                          final int key,
                          final int keyMin,
                          final int keyMax,
                          final int state) {
        super(bytes, state);
        KEYBYTES     = key;
        KEYBYTES_MIN = keyMin;
        KEYBYTES_MAX = keyMax;
        BYTES_MIN    = bytesMin;
        BYTES_MAX    = bytesMax;
    }

    /**
     *
     * @return
     */
    public final int bytesMin() {
        return BYTES_MIN;
    }

    /**
     *
     * @return
     */
    public final int bytesMax() {
        return BYTES_MAX;
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
    public final int keyBytesMin() {
        return KEYBYTES_MIN;
    }

    /**
     *
     * @return
     */
    public final int keyBytesMax() {
        return KEYBYTES_MAX;
    }

    /**
     *
     * @param dstHash
     * @param src
     * @param key
     * @throws StodiumException
     */
    public abstract void hash(final @NotNull  ByteBuffer dstHash,
                              final @NotNull  ByteBuffer src,
                              final @Nullable ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param key
     * @return
     * @throws StodiumException
     */
    @NotNull
    public abstract Multipart<Hash> init(final @Nullable ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param key
     * @param outlen
     * @return
     * @throws StodiumException
     */
    @NotNull
    public abstract Multipart<Hash> init(final @Nullable ByteBuffer key,
                                         final           int        outlen)
            throws StodiumException;
}
