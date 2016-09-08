package eu.artemisc.stodium;

import org.jetbrains.annotations.NotNull;

/**
 * ConstraintViolationExceptions are thrown whenever an application tries to
 * call a function using incorrect parameters, such as a negative length or a
 * buffer with less space than required by the method's result value.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class ConstraintViolationException
        extends StodiumException {
    ConstraintViolationException() {
        super();
    }

    ConstraintViolationException(final @NotNull String detailMessage) {
        super(detailMessage);
    }

    ConstraintViolationException(final @NotNull Throwable throwable) {
        super(throwable);
    }

    ConstraintViolationException(final @NotNull String detailMessage,
                                 final @NotNull Throwable throwable) {
        super(detailMessage, throwable);
    }
}
