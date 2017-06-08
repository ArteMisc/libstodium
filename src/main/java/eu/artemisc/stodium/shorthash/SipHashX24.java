package eu.artemisc.stodium.shorthash;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class SipHashX24
        extends ShortHash {

    SipHashX24() {
        super(StodiumJNI.crypto_shorthash_siphashx24_bytes(),
                StodiumJNI.crypto_shorthash_siphashx24_keybytes());
    }

    @Override
    public void hash(final @NotNull ByteBuffer out,
                     final @NotNull ByteBuffer in,
                     final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(out);

        Stodium.checkSizeMin(out.remaining(), BYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_shorthash_siphashx24(
                Stodium.ensureUsableByteBuffer(out),
                Stodium.ensureUsableByteBuffer(in),
                Stodium.ensureUsableByteBuffer(key)));
    }
}
