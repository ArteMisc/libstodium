/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.random;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.ReadOnlyBufferException;
import eu.artemisc.stodium.StodiumJNI;

/**
 * RandomBytes builds on top of libsodium's random_bytes as its CSPRNG.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class RandomBytes {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private RandomBytes() {}

    /**
     * nextBytes fills the provided buffer with random bytes, using Sodium's
     * {@code randombytes_buf(void*, size_t)} function.
     *
     * @param buffer
     * @throws ReadOnlyBufferException
     */
    public static void nextBytes(final @NotNull ByteBuffer buffer) {
        Stodium.checkDestinationWritable(buffer);
        StodiumJNI.randombytes_buf(buffer);
    }
}
