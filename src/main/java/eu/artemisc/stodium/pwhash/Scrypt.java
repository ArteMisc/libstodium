/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.pwhash;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.StodiumJNI;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Scrypt {

    // block the constructor
    private Scrypt() {}

    // constants
//  public static final String STRPREFIX            = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_strprefix();
    public static final int    STRBYTES             = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_strbytes();

    public static final int    SALTBYTES            = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_saltbytes();
    public static final int    OPSLIMIT_INTERACTIVE = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive();
    public static final int    MEMLIMIT_INTERACTIVE = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive();
    public static final int    OPSLIMIT_SENSITIVE   = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive();
    public static final int    MEMLIMIT_SENSITIVE   = StodiumJNI.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive();

    // wrappers

    //
    // Key derivation API
    //

    /**
     * pwhashScrypt with default (INTERACTIVE) memlimit and opslimit. Equivalent
     * to calling {@link #pwhashScrypt(ByteBuffer, ByteBuffer, ByteBuffer, int, int)}
     * with {@code opslimit = OPSLIMIT_INTERACTIVE} and {@code memlimit =
     * MEMLIMIT_INTERACTIVE}.
     *
     * @param dstKey
     * @param srcPwd
     * @param srcSalt
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void pwhashScrypt(final @NotNull ByteBuffer dstKey,
                                    final @NotNull ByteBuffer srcPwd,
                                    final @NotNull ByteBuffer srcSalt)
            throws StodiumException {
        pwhashScrypt(dstKey, srcPwd, srcSalt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
    }

    /**
     *
     * @param dstKey
     * @param srcPwd
     * @param srcSalt
     * @param opsLimit
     * @param memLimit
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void pwhashScrypt(final @NotNull ByteBuffer dstKey,
                                    final @NotNull ByteBuffer srcPwd,
                                    final @NotNull ByteBuffer srcSalt,
                                    final          int        opsLimit,
                                    final          int        memLimit)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstKey);

        Stodium.checkSize(srcSalt.remaining(), SALTBYTES);
        Stodium.checkPow2(memLimit);

        Stodium.checkStatus(StodiumJNI.crypto_pwhash_scryptsalsa208sha256(
                Stodium.ensureUsableByteBuffer(dstKey),
                Stodium.ensureUsableByteBuffer(srcPwd),
                Stodium.ensureUsableByteBuffer(srcSalt),
                opsLimit, memLimit));
    }

    //
    // TODO: 26-6-16 String based API
    //
}
