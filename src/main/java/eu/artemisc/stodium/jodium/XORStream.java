package eu.artemisc.stodium.jodium;

import android.support.annotation.NonNull;

import javax.crypto.ShortBufferException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public interface XORStream {
    /**
     *
     * @param dst
     * @param src
     * @throws ShortBufferException
     *
     * @see #XORKeyStream(byte[], int, byte[], int, int)
     */
    void XORKeyStream(@NonNull final byte[] dst,
                      @NonNull final byte[] src)
            throws ShortBufferException;

    void XORKeyStream(@NonNull final byte[] dst,
                      final int dstOffset,
                      @NonNull final byte[] src,
                      final int srcOffset,
                      final int length)
            throws ShortBufferException;
}
