package eu.artemisc.stodium.curve25519;

import android.support.annotation.NonNull;

import java.security.PrivateKey;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Curve25519PrivateKey
        implements PrivateKey {

    public Curve25519PrivateKey(@NonNull final byte[] key) {

    }

    @Override
    public String getAlgorithm() {
        return "Curve25519";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
