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

    ConstraintViolationException(@NotNull final String detailMessage) {
        super(detailMessage);
    }

    ConstraintViolationException(@NotNull final Throwable throwable) {
        super(throwable);
    }

    ConstraintViolationException(@NotNull final String detailMessage,
                                 @NotNull final Throwable throwable) {
        super(detailMessage, throwable);
    }
}
