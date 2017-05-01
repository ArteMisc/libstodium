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
 * OperationFailedException is thrown whenever a native function returns a non-0
 * result code, indicating an error condition.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class OperationFailedException
        extends StodiumException {
    /**
     *
     */
    public OperationFailedException() {
        super();
    }

    /**
     *
     * @param detailMessage
     */
    public OperationFailedException(final @NotNull String detailMessage) {
        super(detailMessage);
    }

    /**
     *
     * @param throwable
     */
    public OperationFailedException(final @NotNull Throwable throwable) {
        super(throwable);
    }

    /**
     *
     * @param detailMessage
     * @param throwable
     */
    public OperationFailedException(final @NotNull String    detailMessage,
                                    final @NotNull Throwable throwable) {
        super(detailMessage, throwable);
    }
}
