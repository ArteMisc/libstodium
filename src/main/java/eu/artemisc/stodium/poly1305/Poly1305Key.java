package eu.artemisc.stodium.poly1305;

import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;

import java.security.Key;
import java.util.Arrays;

import eu.artemisc.stodium.OneTimeAuth;
import eu.artemisc.stodium.crypto.Poly1305Spi;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Poly1305Key
        implements Key {
    @NonNull
    private final byte[] key = new byte[Poly1305Spi.KeyBytes];

    public Poly1305Key(@NonNull final byte[] key) {
        System.arraycopy(key, 0, this.key, 0, this.key.length);
    }

    @NonNull
    @CheckResult
    @Override
    public String getAlgorithm() {
        return OneTimeAuth.PRIMITIVE;
    }

    @NonNull
    @CheckResult
    @Override
    public String getFormat() {
        return "raw";
    }

    @NonNull
    @CheckResult
    @Override
    public byte[] getEncoded() {
        return Arrays.copyOf(key, key.length);
    }
}
