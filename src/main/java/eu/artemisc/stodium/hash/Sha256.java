package eu.artemisc.stodium.hash;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Multipart;
import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Sha256
        extends Hash
        implements Multipart.Spec {

    Sha256() {
        super(StodiumJNI.crypto_hash_sha256_bytes(),
                StodiumJNI.crypto_hash_sha256_statebytes());
    }

    @Override
    public void hash(final @NotNull ByteBuffer dstMac,
                     final @NotNull ByteBuffer src)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstMac);

        Stodium.checkSizeMin(dstMac.remaining(), BYTES);

        Stodium.checkStatus(StodiumJNI.crypto_hash_sha256(
                Stodium.ensureUsableByteBuffer(dstMac),
                Stodium.ensureUsableByteBuffer(src)));
    }

    @NotNull
    @Override
    public Multipart<Hash> init()
            throws StodiumException {
        final ByteBuffer state;

        state = ByteBuffer.allocateDirect(STATEBYTES);
        Stodium.checkStatus(StodiumJNI.crypto_hash_sha256_init(state));

        return new Multipart<>(this, state);
    }

    @Override
    public void update(final @NotNull ByteBuffer state,
                       final @NotNull ByteBuffer in)
            throws StodiumException {
        Stodium.checkDestinationWritable(state);
        Stodium.checkSize(state.remaining(), STATEBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_hash_sha256_update(
                Stodium.ensureUsableByteBuffer(state),
                Stodium.ensureUsableByteBuffer(in)));
    }

    @Override
    public void doFinal(final @NotNull ByteBuffer state,
                        final @NotNull ByteBuffer dst)
            throws StodiumException {
        Stodium.checkDestinationWritable(state);
        Stodium.checkDestinationWritable(dst);

        Stodium.checkSize(state.remaining(), STATEBYTES);
        Stodium.checkSizeMin(dst.remaining(), BYTES);

        Stodium.checkStatus(StodiumJNI.crypto_hash_sha256_final(
                Stodium.ensureUsableByteBuffer(state),
                Stodium.ensureUsableByteBuffer(dst)));
    }
}
