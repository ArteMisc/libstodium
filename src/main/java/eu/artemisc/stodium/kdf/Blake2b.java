package eu.artemisc.stodium.kdf;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public final class Blake2b
        extends Kdf {
    Blake2b() {
        super(StodiumJNI.crypto_kdf_blake2b_bytes_min(),
                StodiumJNI.crypto_kdf_blake2b_bytes_max(),
                StodiumJNI.crypto_kdf_blake2b_contextbytes(),
                StodiumJNI.crypto_kdf_blake2b_keybytes());
    }

    @Override
    public void deriveFromKey(final @NotNull ByteBuffer subKey,
                              final          long       subKeyId,
                              final @NotNull ByteBuffer context,
                              final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(subKey);

        Stodium.checkSize(subKey.remaining(), BYTES_MIN, BYTES_MAX);
        Stodium.checkSize(context.remaining(), CONTEXTBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_kdf_blake2b_derive_from_key(
                Stodium.ensureUsableByteBuffer(subKey),
                subKeyId,
                Stodium.ensureUsableByteBuffer(context),
                Stodium.ensureUsableByteBuffer(key)));
    }
}
