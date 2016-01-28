package eu.artemisc.stodium.crypto.curve25519;

import java.security.PublicKey;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Curve25519PublicKey
        implements PublicKey {
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
