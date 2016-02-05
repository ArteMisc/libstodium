package eu.artemisc.stodium.crypto.poly1305;

import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;

import eu.artemisc.stodium.Poly1305;

/**
 * Poly1305Spi implements the {@link javax.crypto.MacSpi} interface, built on
 * top of libsodium's implementation of Poly1305.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Poly1305Spi
        extends MacSpi {
    public static final int KeyBytes = Poly1305.KEYBYTES;
    public static final int TagBytes = Poly1305.BYTES;

    @NonNull
    private final byte[] key = new byte[KeyBytes];
    @Nullable
    private Poly1305 state = null;

    /**
     * engineGetMacLength returns the length of a Poly1305 Tag, which is 16
     * bytes.
     *
     * @return OneTimeAuth.BYTES
     */
    @CheckResult
    @Override
    protected int engineGetMacLength() {
        return TagBytes;
    }

    /**
     * engineInit puts the instance in it's initial state.
     *
     * @param key a 32 byte key
     * @param params this parameter is ignored
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    @Override
    protected void engineInit(@NonNull final Key key,
                              @Nullable final AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof Poly1305Key)) {
            throw new InvalidKeyException(
                    "Poly1305Spi expects a Poly1305Key instance");
        }
        System.arraycopy(key.getEncoded(), 0, this.key, 0, this.key.length);
        engineReset();
    }

    @Override
    protected void engineUpdate(final byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(@NonNull final byte[] input,
                                final int offset,
                                final int len) {
        if (state == null) {
            throw new NullPointerException("Poly1305 State is null");
        }
        state.update(input, offset, len);
    }

    @NonNull
    @CheckResult
    @Override
    protected byte[] engineDoFinal() {
        if (state == null) {
            throw new NullPointerException("Poly1305 State is null");
        }
        final byte[] out = new byte[TagBytes];

        state.doFinal(out);
        state = null;
        return out;
    }

    @Override
    protected void engineReset() {
        state = new Poly1305(this.key);
    }
}
