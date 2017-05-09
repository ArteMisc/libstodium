package eu.artemisc.stodium.generichash;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Multipart;
import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;
import eu.artemisc.stodium.hash.Hash;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Blake
        extends GenericHash
        implements Multipart.Spec {

    Blake() {
        super(StodiumJNI.crypto_generichash_blake2b_bytes(),
                StodiumJNI.crypto_generichash_blake2b_bytes_min(),
                StodiumJNI.crypto_generichash_blake2b_bytes_max(),
                StodiumJNI.crypto_generichash_blake2b_keybytes(),
                StodiumJNI.crypto_generichash_blake2b_keybytes_min(),
                StodiumJNI.crypto_generichash_blake2b_keybytes_max(),
                StodiumJNI.crypto_generichash_blake2b_statebytes());
    }

    @Override
    public void hash(final @NotNull ByteBuffer dstHash,
                     final @NotNull ByteBuffer src)
            throws StodiumException {
        hash(dstHash, src, null);
    }

    @Override
    public void hash(final @NotNull  ByteBuffer dstHash,
                     final @NotNull  ByteBuffer src,
                     final @Nullable ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstHash);

        if (key != null) {
            Stodium.checkSize(key.remaining(), KEYBYTES_MIN, KEYBYTES_MAX);
        }

        Stodium.checkStatus(StodiumJNI.crypto_generichash_blake2b(
                Stodium.ensureUsableByteBuffer(dstHash),
                Stodium.ensureUsableByteBuffer(src),
                key == null ? null : Stodium.ensureUsableByteBuffer(key)));
    }

    @NotNull
    @Override
    public Multipart<Hash> init()
            throws StodiumException {
        return init(null);
    }

    @NotNull
    @Override
    public Multipart<Hash> init(final @Nullable ByteBuffer key)
            throws StodiumException {
        return init(key, BYTES);
    }

    @NotNull
    @Override
    public Multipart<Hash> init(final @Nullable ByteBuffer key,
                                final           int        outlen)
            throws StodiumException {
        final ByteBuffer state;

        if (key != null) {
            Stodium.checkSize(key.remaining(), KEYBYTES_MIN, KEYBYTES_MAX);
        }
        Stodium.checkSize(outlen, BYTES_MIN, BYTES_MAX);
        state = ByteBuffer.allocateDirect(STATEBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_generichash_blake2b_init(
                state, key == null ? null : Stodium.ensureUsableByteBuffer(key), outlen));

        return new Multipart<>(this, state);
    }

    @Override
    public void update(final @NotNull ByteBuffer state,
                       final @NotNull ByteBuffer in)
            throws StodiumException {
        Stodium.checkDestinationWritable(state);
        Stodium.checkSize(state.remaining(), STATEBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_generichash_blake2b_update(
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
        Stodium.checkSizeMin(dst.remaining(), BYTES_MIN);

        Stodium.checkStatus(StodiumJNI.crypto_generichash_blake2b_final(
                Stodium.ensureUsableByteBuffer(state),
                Stodium.ensureUsableByteBuffer(dst)));
    }
}
