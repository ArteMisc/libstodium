package eu.artemisc.stodium;

import android.support.annotation.NonNull;

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

    StodiumException(@NonNull final String detailMessage) {
        super(detailMessage);
    }

    StodiumException(@NonNull final Throwable throwable) {
        super(throwable);
    }

    StodiumException(@NonNull final String detailMessage,
                     @NonNull final Throwable throwable) {
        super(detailMessage, throwable);
    }
}
