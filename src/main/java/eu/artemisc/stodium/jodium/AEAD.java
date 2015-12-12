package eu.artemisc.stodium.jodium;

import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;

import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public interface AEAD {
    @CheckResult
    int nonceSize();

    @CheckResult
    int Overhead();

    /**
     *
     * @param dst
     * @param nonce
     * @param src
     * @param data
     */
    void seal(@NonNull final byte[] dst,
              @NonNull final byte[] nonce,
              @NonNull final byte[] src,
              @NonNull final byte[] data)
            throws ShortBufferException;

    /**
     *
     * @param dst
     * @param nonce
     * @param src
     * @param data
     * @throws AEADBadTagException
     */
    void open(@NonNull final byte[] dst,
              @NonNull final byte[] nonce,
              @NonNull final byte[] src,
              @NonNull final byte[] data)
            throws AEADBadTagException, ShortBufferException;
}
