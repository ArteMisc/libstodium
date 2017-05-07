/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.auth;

import org.abstractj.kalium.Sodium;
import org.jetbrains.annotations.NotNull;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * Auth wraps calls to crypto_auth, based on HMAC-SHA512256
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Auth {

    // block the constructor
    private Auth() {}

    // constants
    public static final int BYTES    = 32;
    public static final int KEYBYTES = 32;

    public static final @NotNull String PRIMITIVE = Sodium.crypto_auth_primitive();

    // wrappers

    /**
     *
     * @param dstOut
     * @param srcIn
     * @param srcKey
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void auth(final @NotNull byte[] dstOut,
                            final @NotNull byte[] srcIn,
                            final @NotNull byte[] srcKey)
            throws StodiumException {
        Stodium.checkSize(dstOut.length, BYTES);
        Stodium.checkSize(srcKey.length, KEYBYTES);
        Stodium.checkStatus(
                Sodium.crypto_auth(dstOut, srcIn, srcIn.length, srcKey));
    }

    /**
     *
     * @param srcTag
     * @param srcIn
     * @param srcKey
     * @return
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static boolean authVerify(final @NotNull byte[] srcTag,
                                     final @NotNull byte[] srcIn,
                                     final @NotNull byte[] srcKey)
            throws StodiumException {
        Stodium.checkSize(srcTag.length, BYTES);
        Stodium.checkSize(srcKey.length, KEYBYTES);
        return Sodium.crypto_auth_verify(
                srcTag, srcIn, srcIn.length, srcKey) == 0;
    }
}
