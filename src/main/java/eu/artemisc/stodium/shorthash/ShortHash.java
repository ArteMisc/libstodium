/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.shorthash;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * ShortHash wraps calls to sodium's crypto_shorthash API.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class ShortHash {

    // block the constructor
    private ShortHash() {}

    // constants
    public static final int BYTES    = Sodium.crypto_shorthash_bytes();
    public static final int KEYBYTES = Sodium.crypto_shorthash_keybytes();

    public static final @NotNull String PRIMITIVE = Sodium.crypto_shorthash_primitive();

    /**
     *
     * @param srcIn
     * @param srcKey
     * @return a Long that holds the (BigEndian) representation of the resulting
     *         64-bit Hash value.
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    @NotNull
    static Long shorthash(final @NotNull byte[] srcIn,
                          final @NotNull byte[] srcKey)
            throws StodiumException {
        Stodium.checkSize(srcKey.length, KEYBYTES);

        byte[] dst = new byte[BYTES];
        Stodium.checkStatus(
                Sodium.crypto_shorthash(dst, srcIn, srcIn.length, srcKey));

        // Return as long
        return ByteBuffer.wrap(dst)
                .order(ByteOrder.BIG_ENDIAN)
                .getLong();
    }

    /**
     *
     * @param dstHash The destination array to which the resulting 8-byte hash.
     *                The bytes are considered to be BigEndian.
     * @param srcIn
     * @param srcKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    static void shorthash(final @NotNull byte[] dstHash,
                          final @NotNull byte[] srcIn,
                          final @NotNull byte[] srcKey)
            throws StodiumException {
        Stodium.checkSize(dstHash.length, BYTES);
        Stodium.checkSize(srcKey.length, KEYBYTES);
        Stodium.checkStatus(
                Sodium.crypto_shorthash(dstHash, srcIn, srcIn.length, srcKey));
    }
}
