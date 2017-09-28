package eu.artemisc.stodium.codecs;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Hex
        extends Codec {

    @Override
    public int encodedLength(final int input) {
        return input * 2;
    }

    @Override
    public void encode(final @NotNull ByteBuffer dst,
                       final @NotNull ByteBuffer src)
            throws StodiumException {
        Stodium.checkDestinationWritable(dst);

        Stodium.checkSizeMin(dst.remaining(), encodedLength(src.remaining()));

        Stodium.checkStatus(StodiumJNI.sodium_bin2hex(
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(src)));
    }

    @Override
    public void decode(final @NotNull ByteBuffer dst,
                       final @NotNull ByteBuffer src)
            throws StodiumException {
        Stodium.checkDestinationWritable(dst);

        Stodium.checkSizeMin(encodedLength(dst.remaining()), src.remaining());

        Stodium.checkStatus(StodiumJNI.sodium_hex2bin(
                Stodium.ensureUsableByteBuffer(dst),
                Stodium.ensureUsableByteBuffer(src)));
    }
}
