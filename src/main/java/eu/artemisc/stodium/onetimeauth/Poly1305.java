package eu.artemisc.stodium.onetimeauth;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Multipart;
import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.auth.Auth;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class Poly1305
        extends OneTimeAuth
        implements Multipart.Spec {

    Poly1305() {
        super(StodiumJNI.crypto_onetimeauth_poly1305_bytes(),
                StodiumJNI.crypto_onetimeauth_poly1305_keybytes(),
                StodiumJNI.crypto_onetimeauth_poly1305_statebytes());
    }

    @Override
    public void mac(final @NotNull ByteBuffer dstMac,
                    final @NotNull ByteBuffer src,
                    final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstMac);

        Stodium.checkSizeMin(dstMac.remaining(), BYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_onetimeauth_poly1305(
                Stodium.ensureUsableByteBuffer(dstMac),
                Stodium.ensureUsableByteBuffer(src),
                Stodium.ensureUsableByteBuffer(key)));
    }

    @Override
    public boolean verify(final @NotNull ByteBuffer srcMac,
                          final @NotNull ByteBuffer src,
                          final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkSizeMin(srcMac.remaining(), BYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        return StodiumJNI.NOERR == StodiumJNI.crypto_onetimeauth_poly1305_verify(
                Stodium.ensureUsableByteBuffer(srcMac),
                Stodium.ensureUsableByteBuffer(src),
                Stodium.ensureUsableByteBuffer(key));
    }

    @NotNull
    @Override
    public Multipart<Auth> init(final @NotNull ByteBuffer key)
            throws StodiumException {
        final ByteBuffer state;

        Stodium.checkSize(key.remaining(), KEYBYTES);
        state = ByteBuffer.allocateDirect(STATEBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_onetimeauth_poly1305_init(
                state, Stodium.ensureUsableByteBuffer(key)));

        return new Multipart<>(this, state);
    }

    @Override
    public void update(final @NotNull ByteBuffer state,
                       final @NotNull ByteBuffer in)
            throws StodiumException {
        Stodium.checkDestinationWritable(state);
        Stodium.checkSize(state.remaining(), STATEBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_onetimeauth_poly1305_update(
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

        Stodium.checkStatus(StodiumJNI.crypto_onetimeauth_poly1305_final(
                Stodium.ensureUsableByteBuffer(state),
                Stodium.ensureUsableByteBuffer(dst)));
    }
}
