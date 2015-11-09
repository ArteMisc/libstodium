package eu.artemisc.stodium.auth;

import android.support.annotation.NonNull;

import org.abstractj.kalium.Sodium;

import eu.artemisc.stodium.Stodium;

/**
 * OneTimeAuth wraps calls to crypto_onetimeauth, a message authentication code
 * based on Poly1305.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class OneTimeAuth {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // block the constructor
    private OneTimeAuth() {}

    // constants
    public static final int BYTES = 16;
    public static final int KEYBYTES = 32;

    // wrappers

    //
    // non-stream methods
    //

    /**
     *
     * @param dstOut
     * @param srcIn
     * @param srcKey
     * @throws SecurityException
     */
    public static void auth(@NonNull final byte[] dstOut,
                            @NonNull final byte[] srcIn,
                            @NonNull final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(dstOut.length, BYTES, "OneTimeAuth.BYTES");
        Stodium.checkSize(srcKey.length, KEYBYTES, "OneTimeAuth.KEYBYTES");
        Stodium.checkStatus(
                Sodium.crypto_onetimeauth(dstOut, srcIn, srcIn.length, srcKey));
    }

    /**
     *
     * @param srcTag
     * @param srcIn
     * @param srcKey
     * @return
     * @throws SecurityException
     */
    public static boolean authVerify(@NonNull final byte[] srcTag,
                                     @NonNull final byte[] srcIn,
                                     @NonNull final byte[] srcKey)
            throws SecurityException {
        Stodium.checkSize(srcTag.length, BYTES, "OneTimeAuth.BYTES");
        Stodium.checkSize(srcKey.length, KEYBYTES, "OneTimeAuth.KEYBYTES");
        return Sodium.crypto_onetimeauth_verify(
                srcTag, srcIn, srcIn.length, srcKey) == 0;
    }
}
