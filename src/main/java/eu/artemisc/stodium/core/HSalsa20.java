/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.core;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.StodiumJNI;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class HSalsa20 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // constants
    public static final int INPUTBYTES  = StodiumJNI.crypto_core_hsalsa20_inputbytes();
    public static final int OUTPUTBYTES = StodiumJNI.crypto_core_hsalsa20_outputbytes();
    public static final int CONSTBYTES  = StodiumJNI.crypto_core_hsalsa20_constbytes();
    public static final int KEYBYTES    = StodiumJNI.crypto_core_hsalsa20_keybytes();

    /**
     *
     * @param dst
     * @param src
     * @param key
     * @param constant
     * @throws StodiumException
     * @throws IllegalArgumentException
     */
    public static void hsalsa20(final @NotNull  ByteBuffer dst,
                                final @NotNull  ByteBuffer src,
                                final @NotNull  ByteBuffer key,
                                final @Nullable ByteBuffer constant)
            throws StodiumException {
        Stodium.checkDestinationWritable(dst, "Stodium.HSalsa20#hsalsa20(dst)");

        Stodium.checkSize(dst.remaining(), OUTPUTBYTES, "HSalsa20.OUTPUTBYTES");
        Stodium.checkSize(src.remaining(), INPUTBYTES,  "HSalsa20.INPUTBYTES");
        Stodium.checkSize(key.remaining(), KEYBYTES,    "HSalsa20.KEYBYTES");
        if (constant != null) {
            Stodium.checkSize(constant.remaining(), CONSTBYTES, "HSalsa20.CONSTBYTES");
        }

        StodiumJNI.crypto_core_hsalsa20(
                Stodium.ensureUsableByteBuffer(dst.slice()),
                Stodium.ensureUsableByteBuffer(src.slice()),
                Stodium.ensureUsableByteBuffer(key.slice()),
                constant == null ? null : Stodium.ensureUsableByteBuffer(constant.slice()));
    }
}
