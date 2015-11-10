package eu.artemisc.stodium.hash;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import eu.artemisc.stodium.Stodium;

/**
 * GenericHash wraps calls to crypto_generichash, based on BLAKE2b.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class GenericHash {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private GenericHash() {}

    // constants
    public static final int BYTES = 32;
    public static final int BYTES_MIN = 16;
    public static final int BYTES_MAX = 64;
    public static final int KEYBYTES = 32;
    public static final int KEYBYTES_MIN = 16;
    public static final int KEYBYTES_MAX = 64;

    public static final int SALTBYTES = 16;
    public static final int PERSONALBYTES = 16;

    // wrappers

    public static void genericHash(@NonNull final byte[] dstHash,
                                   @NonNull final byte[] srcInput,
                                   @NonNull final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(dstHash.length, BYTES_MIN, BYTES_MAX,
                "GenericHash.BYTES_MIN", "GenericHash.BYTES_MAX");
        Stodium.checkSize(srcKey.length, KEYBYTES_MIN, KEYBYTES_MAX,
                "GenericHash.KEYBYTES_MIN", "GenericHash.KEYBYTES_MAX");
        Stodium.checkStatus(Sodium.crypto_generichash(dstHash, dstHash.length,
                srcInput, srcInput.length, srcKey, srcKey.length));
    }
}
