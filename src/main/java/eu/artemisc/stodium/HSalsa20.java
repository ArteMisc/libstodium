package eu.artemisc.stodium;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.nio.ByteBuffer;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class HSalsa20 {
    static {
        // Require sodium_init();
        Stodium.StodiumInit();
    }

    // constants
    public static final int INPUTBYTES  = StodiumJNI.crypto_core_hsalsa20_inputbytes();
    public static final int OUTPUTBYTES = StodiumJNI.crypto_core_hsalsa20_outputbytes();
    public static final int CONSTBYTES  = StodiumJNI.crypto_core_hsalsa20_constbytes();
    public static final int KEYBYTES    = StodiumJNI.crypto_core_hsalsa20_keybytes();

    /**
     *
     * @param dst
     * @param src
     * @param key
     * @param constant
     * @throws StodiumException
     * @throws IllegalArgumentException
     */
    public static void hsalsa20(@NonNull  final ByteBuffer dst,
                                @NonNull  final ByteBuffer src,
                                @NonNull  final ByteBuffer key,
                                @Nullable final ByteBuffer constant)
            throws StodiumException {
        if (dst.isReadOnly()) {
            throw new IllegalArgumentException("dst is readonly");
        }

        Stodium.checkSize(dst.remaining(), OUTPUTBYTES, "HSalsa20.OUTPUTBYTES");
        Stodium.checkSize(src.remaining(), INPUTBYTES,  "HSalsa20.INPUTBYTES");
        Stodium.checkSize(key.remaining(), KEYBYTES,    "HSalsa20.KEYBYTES");
        if (constant != null) {
            Stodium.checkSize(constant.remaining(), CONSTBYTES, "HSalsa20.CONSTBYTES");
        }

        StodiumJNI.crypto_core_hsalsa20(
                Stodium.ensureUsableByteBuffer(dst.slice()),
                Stodium.ensureUsableByteBuffer(src.slice()),
                Stodium.ensureUsableByteBuffer(key.slice()),
                constant == null ? null : Stodium.ensureUsableByteBuffer(constant.slice()));
    }
}
