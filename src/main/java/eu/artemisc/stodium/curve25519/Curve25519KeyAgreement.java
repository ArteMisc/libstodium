package eu.artemisc.stodium.curve25519;

import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.Size;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import eu.artemisc.stodium.box.Box;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Curve25519KeyAgreement
        extends KeyAgreementSpi {
    @Nullable private Curve25519PrivateKey privateKey;
    @Nullable private Curve25519PublicKey publicKey;

    @Nullable
    @Override
    protected Key engineDoPhase(@NonNull final Key key,
                                final boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (!lastPhase) {
            throw new IllegalStateException("Curve25519 cannot have more than 1 phase");
        }
        if (!(key instanceof Curve25519PublicKey)) {
            throw new InvalidKeyException("Key needs to be Curve25519PublicKey");
        }

        publicKey = (Curve25519PublicKey) key;
        return null;
    }

    @NonNull
    @Size(32) // Curve25519.BYTES
    @CheckResult
    @Override
    protected byte[] engineGenerateSecret()
            throws IllegalStateException {
        if (privateKey == null || publicKey == null) {
            throw new IllegalStateException("Agreement not yet finished");
        }

        byte[] secret = new byte[Curve25519.BYTES];
        // FIXME implement Curve.beforenm
        return secret;
    }

    @Override
    protected int engineGenerateSecret(@NonNull final byte[] sharedSecret,
                                       final int offset)
            throws IllegalStateException, ShortBufferException {
        if (sharedSecret.length - offset < Curve25519.BYTES) {
            throw new ShortBufferException();
        }

        byte[] tmp = engineGenerateSecret();
        System.arraycopy(tmp, 0, sharedSecret, offset, Curve25519.BYTES);
        return Curve25519.BYTES;
    }

    @NonNull
    @Override
    protected SecretKey engineGenerateSecret(@NonNull final String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        return null; // FIXME TODO
    }

    @Override
    protected void engineInit(@NonNull final Key key,
                              @NonNull final SecureRandom random)
            throws InvalidKeyException {
        if (privateKey != null || publicKey != null) {
            throw new IllegalStateException("Key(s) already set");
        }


    }

    @Override
    protected void engineInit(@NonNull final Key key,
                              @NonNull final AlgorithmParameterSpec params,
                              @NonNull final SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

    }
}
