/*
 * Copyright (c) 2017 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.scalarmult;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Curve25519
        extends ScalarMult {

    Curve25519() {
        super(StodiumJNI.crypto_scalarmult_curve25519_bytes(),
                StodiumJNI.crypto_scalarmult_curve25519_scalarbytes());
    }

    @Override
    public void scalarMult(final @NotNull ByteBuffer dst,
                           final @NotNull ByteBuffer src,
                           final @NotNull ByteBuffer groupElement)
            throws StodiumException {
        Stodium.checkSize(groupElement.remaining(), SCALARBYTES);
        Stodium.checkSize(src.remaining(), BYTES);
        Stodium.checkSizeMin(dst.remaining(), BYTES);
        Stodium.checkStatus(StodiumJNI.crypto_scalarmult_curve25519(
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(src),
                Stodium.ensureUsableByteBuffer(groupElement)));
    }

    @Override
    public void scalarMultBase(final @NotNull ByteBuffer dst,
                               final @NotNull ByteBuffer src)
            throws StodiumException {
        Stodium.checkSize(src.remaining(), BYTES);
        Stodium.checkSizeMin(dst.remaining(), BYTES);
        Stodium.checkStatus(StodiumJNI.crypto_scalarmult_curve25519_base(
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(src)));
    }
}
