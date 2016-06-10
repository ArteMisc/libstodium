package eu.artemisc.stodium;

import android.support.annotation.NonNull;

/**
 * ReadOnlyBufferException is a mirror of
 * {@link java.nio.ReadOnlyBufferException} that accepts a description of the
 * buffer variable that was incorrectly set to being read-only. It extends the
 * same {@link UnsupportedOperationException}, as they both indicate the same
 * type of programming/runtime errors.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 *
 * @see java.nio.ReadOnlyBufferException
 */
public class ReadOnlyBufferException
        extends UnsupportedOperationException {
    ReadOnlyBufferException(@NonNull final String detailMessage) {
        super(detailMessage);
    }
}
