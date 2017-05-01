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
 * ConstraintViolationExceptions are thrown whenever an application tries to
 * call a function using incorrect parameters, such as a negative length or a
 * buffer with less space than required by the method's result value.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class ConstraintViolationException
        extends StodiumException {
    /**
     *
     */
    public ConstraintViolationException() {
        super();
    }

    /**
     *
     * @param detailMessage
     */
    public ConstraintViolationException(final @NotNull String detailMessage) {
        super(detailMessage);
    }

    /**
     *
     * @param throwable
     */
    public ConstraintViolationException(final @NotNull Throwable throwable) {
        super(throwable);
    }

    /**
     *
     * @param detailMessage
     * @param throwable
     */
    public ConstraintViolationException(final @NotNull String    detailMessage,
                                        final @NotNull Throwable throwable) {
        super(detailMessage, throwable);
    }
}
