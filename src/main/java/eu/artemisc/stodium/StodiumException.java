package eu.artemisc.stodium;

import org.jetbrains.annotations.NotNull;

import java.security.GeneralSecurityException;

/**
 * StodiumException
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class StodiumException
        extends GeneralSecurityException {
    StodiumException() {
        super();
    }

    StodiumException(final @NotNull String detailMessage) {
        super(detailMessage);
    }

    StodiumException(final @NotNull Throwable throwable) {
        super(throwable);
    }

    StodiumException(final @NotNull String detailMessage,
                     final @NotNull Throwable throwable) {
        super(detailMessage, throwable);
    }
}
