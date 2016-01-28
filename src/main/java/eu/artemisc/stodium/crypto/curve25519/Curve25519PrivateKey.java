package eu.artemisc.stodium.crypto.curve25519;

import java.math.BigInteger;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Curve25519PrivateKey
        extends DHPrivateKeySpec
        implements DHPrivateKey {
    class ParamSpec extends DHParameterSpec {

        /**
         *
         * @param p
         * @param g
         */
        public ParamSpec(BigInteger p, BigInteger g) {
            super(p, g);
        }

        /**
         *
         * @param p
         * @param g
         * @param l
         */
        public ParamSpec(BigInteger p, BigInteger g, int l) {
            super(p, g, l);
        }
    }


    /**
     * Creates a new <code>DHPrivateKeySpec</code> with the specified <i>private
     * value</i> <code>x</code>. <i>prime modulus</i> <code>p</code> and <i>base
     * generator</i> <code>g</code>.
     *
     * @param x the private value.
     * @param p the prime modulus.
     * @param g
     */
    public Curve25519PrivateKey(BigInteger x, BigInteger p, BigInteger g) {
        super(x, p, g);
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

    @Override
    public DHParameterSpec getParams() {
        return null;
    }
}
