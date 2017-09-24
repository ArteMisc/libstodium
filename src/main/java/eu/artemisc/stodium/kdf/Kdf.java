package eu.artemisc.stodium.kdf;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Kdf {
    private static final @NotNull Singleton<Kdf> BLAKE = new Singleton<Kdf>() {
        @NotNull
        @Override
        protected Kdf initialize() {
            return new Blake2b();
        }
    };

    @NotNull
    public static Kdf instance() {
        return blake2b();
    }

    @NotNull
    public static Kdf blake2b() {
        return BLAKE.get();
    }

    // constants
    final int BYTES_MIN;
    final int BYTES_MAX;
    final int CONTEXTBYTES;
    final int KEYBYTES;

    Kdf(final int min,
        final int max,
        final int ctx,
        final int key) {
        BYTES_MIN = min;
        BYTES_MAX = max;
        CONTEXTBYTES = ctx;
        KEYBYTES = key;
    }

    /**
     *
     * @return
     */
    public final int bytesMin() {
        return BYTES_MIN;
    }

    /**
     *
     * @return
     */
    public final int bytesMax() {
        return BYTES_MAX;
    }

    /**
     *
     * @return
     */
    public final int contextBytes() {
        return CONTEXTBYTES;
    }

    /**
     *
     * @return
     */
    public final int keyBytes() {
        return KEYBYTES;
    }

    /**
     *
     * @param subKey
     * @param subKeyId
     * @param context
     * @param key
     * @throws StodiumException
     */
    public abstract void deriveFromKey(final @NotNull ByteBuffer subKey,
                                       final          long       subKeyId,
                                       final @NotNull ByteBuffer context,
                                       final @NotNull ByteBuffer key)
            throws StodiumException;
}
