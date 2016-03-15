package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import org.abstractj.kalium.Sodium;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class HSalsa20 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // constants
    public static final int INPUTBYTES  = Sodium.crypto_core_hsalsa20_inputbytes();
    public static final int OUTPUTBYTES = Sodium.crypto_core_hsalsa20_outputbytes();
    public static final int CONSTBYTES  = Sodium.crypto_core_hsalsa20_constbytes();
    public static final int KEYBYTES    = Sodium.crypto_core_hsalsa20_keybytes();

    /**
     *
     * @param dst
     * @param src
     * @param key
     * @param constant
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    public static void hsalsa20(@NonNull final byte[] dst,
                                @NonNull final byte[] src,
                                @NonNull final byte[] key,
                                @Nullable final byte[] constant)
            throws StodiumException {
        if (constant != null) {
            Stodium.checkSize(constant.length, CONSTBYTES, "HSalsa20.CONSTBYTES");
        }
        Stodium.checkSize(dst.length, OUTPUTBYTES, "HSalsa20.OUTPUTBYTES");
        Stodium.checkSize(src.length, INPUTBYTES, "HSalsa20.INPUTBYTES");
        Stodium.checkSize(key.length, KEYBYTES, "HSalsa20.KEYBYTES");
        Stodium.checkStatus(Sodium.crypto_core_hsalsa20(
                dst, src, key, constant));
    }
}
