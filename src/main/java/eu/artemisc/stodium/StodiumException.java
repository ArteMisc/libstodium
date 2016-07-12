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

    StodiumException(@NotNull final String detailMessage) {
        super(detailMessage);
    }

    StodiumException(@NotNull final Throwable throwable) {
        super(throwable);
    }

    StodiumException(@NotNull final String detailMessage,
                     @NotNull final Throwable throwable) {
        super(detailMessage, throwable);
    }
}
