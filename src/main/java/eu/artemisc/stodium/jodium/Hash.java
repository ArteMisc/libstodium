package eu.artemisc.stodium.jodium;

import android.support.annotation.NonNull;

import java.io.OutputStream;

import javax.crypto.ShortBufferException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Hash
        extends OutputStream {
    @NonNull
    public byte[] sum() {
        final byte[] s = new byte[size()];
        try { sum(s, 0); } catch (ShortBufferException ignored) { }
        return s;
    }

    public final void sum(@NonNull final byte[] out)
            throws ShortBufferException {
        sum(out, 0);
    }

    /**
     *
     * @param out
     * @param offset
     * @throws ShortBufferException
     */
    public abstract void sum(@NonNull final byte[] out,
                             final int offset)
            throws ShortBufferException;

    public abstract int size();

    public abstract int blockSize();
}
