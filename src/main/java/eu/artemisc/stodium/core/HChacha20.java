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

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class HChacha20
        extends Core {

    HChacha20() {
        super(StodiumJNI.crypto_core_hchacha20_inputbytes(),
              StodiumJNI.crypto_core_hchacha20_outputbytes(),
              StodiumJNI.crypto_core_hchacha20_constbytes(),
              StodiumJNI.crypto_core_hchacha20_keybytes());
    }

    @Override
    public void hash(final @NotNull  ByteBuffer dst,
                     final @NotNull  ByteBuffer src,
                     final @NotNull  ByteBuffer key,
                     final @Nullable ByteBuffer constant)
            throws StodiumException {
        Stodium.checkDestinationWritable(dst);

        Stodium.checkSize(dst.remaining(), OUTPUTBYTES);
        Stodium.checkSize(src.remaining(), INPUTBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);
        if (constant != null) {
            Stodium.checkSize(constant.remaining(), CONSTBYTES);
        }

        StodiumJNI.crypto_core_hchacha20(
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(src),
                Stodium.ensureUsableByteBuffer(key),
                constant == null ? null : Stodium.ensureUsableByteBuffer(constant));
    }
}
