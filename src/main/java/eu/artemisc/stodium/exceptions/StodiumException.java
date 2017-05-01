/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.exceptions;

import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;

/**
 * StodiumException
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class StodiumException
        extends GeneralSecurityException {
    /**
     *
     */
    StodiumException() {
        super();
    }

    /**
     *
     * @param detailMessage
     */
    StodiumException(final @NotNull String detailMessage) {
        super(detailMessage);
    }

    /**
     *
     * @param throwable
     */
    StodiumException(final @NotNull Throwable throwable) {
        super(throwable);
    }

    /**
     *
     * @param detailMessage
     * @param throwable
     */
    StodiumException(final @NotNull String    detailMessage,
                     final @NotNull Throwable throwable) {
        super(detailMessage, throwable);
    }
}
