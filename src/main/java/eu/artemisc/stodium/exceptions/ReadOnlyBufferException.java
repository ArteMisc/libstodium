/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.exceptions;

import org.jetbrains.annotations.NotNull;

/**
 * ReadOnlyBufferException is a mirror of
 * {@link java.nio.ReadOnlyBufferException} that accepts a description of the
 * buffer variable that was incorrectly set to being read-only. It extends the
 * {@link IllegalArgumentException}, as they both indicate the same type of
 * programming/runtime errors.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 *
 * @see java.nio.ReadOnlyBufferException
 */
public final class ReadOnlyBufferException
        extends IllegalArgumentException {
    /**
     *
     */
    public ReadOnlyBufferException() {
        super();
    }

    /**
     *
     * @param detailMessage
     */
    public ReadOnlyBufferException(final @NotNull String detailMessage) {
        super(detailMessage);
    }
}
