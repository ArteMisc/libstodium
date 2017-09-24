package eu.artemisc.stodium.codecs;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class Base64
        extends Codec {

    private final int variant;

    Base64(final int variant) {
        this.variant = variant;
    }

    @Override
    public int encodedLength(final int input) {
        return StodiumJNI.sodium_base64_encoded_len(input, variant);
    }

    @Override
    public void encode(final @NotNull ByteBuffer dst,
                       final @NotNull ByteBuffer src)
            throws StodiumException {
        Stodium.checkDestinationWritable(dst);

        Stodium.checkSizeMin(dst.remaining(), encodedLength(src.remaining()));

        Stodium.checkStatus(StodiumJNI.sodium_bin2base64(
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(src),
                variant));
    }

    @Override
    public void decode(final @NotNull ByteBuffer dst,
                       final @NotNull ByteBuffer src)
            throws StodiumException {
        Stodium.checkDestinationWritable(dst);

        Stodium.checkStatus(StodiumJNI.sodium_base642bin(
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(src),
                variant));
    }
}
