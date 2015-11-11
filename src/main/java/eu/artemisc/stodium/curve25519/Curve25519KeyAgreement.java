package eu.artemisc.stodium.curve25519;

import android.support.annotation.NonNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Curve25519KeyAgreement
        extends KeyAgreementSpi {

    @Override
    protected Key engineDoPhase(@NonNull final Key key,
                                final boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        return null;
    }

    @NonNull
    @Override
    protected byte[] engineGenerateSecret()
            throws IllegalStateException {
        return new byte[0];
    }

    @Override
    protected int engineGenerateSecret(@NonNull final byte[] sharedSecret,
                                       final int offset)
            throws IllegalStateException, ShortBufferException {
        return 0;
    }

    @NonNull
    @Override
    protected SecretKey engineGenerateSecret(@NonNull final String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        return null;
    }

    @Override
    protected void engineInit(@NonNull final Key key,
                              @NonNull final SecureRandom random)
            throws InvalidKeyException {

    }

    @Override
    protected void engineInit(@NonNull final Key key,
                              @NonNull final AlgorithmParameterSpec params,
                              @NonNull final SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

    }
}
