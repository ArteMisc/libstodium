package eu.artemisc.stodium.crypto.curve25519;

import android.support.annotation.NonNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Curve25519KeyPairGenerator
        extends KeyPairGeneratorSpi {
    @Override
    public KeyPair generateKeyPair() {
        return null;
    }

    @Override
    public void initialize(@NonNull final AlgorithmParameterSpec params,
                           @NonNull final SecureRandom random)
            throws InvalidAlgorithmParameterException {
        super.initialize(params, random);
    }

    @Override
    public void initialize(final int keysize,
                           @NonNull final SecureRandom random) {

    }
}
