package eu.artemisc.stodium.secretbox;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Stodium;
import eu.artemisc.stodium.StodiumJNI;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
final class XSalsa20Poly1305
        extends SecretBox {

    XSalsa20Poly1305() {
        super(StodiumJNI.crypto_secretbox_xsalsa20poly1305_keybytes(),
                StodiumJNI.crypto_secretbox_xsalsa20poly1305_macbytes(),
                StodiumJNI.crypto_secretbox_xsalsa20poly1305_noncebytes());
    }

    @Override
    public void easy(final @NotNull ByteBuffer dstCipher,
                     final @NotNull ByteBuffer srcPlain,
                     final @NotNull ByteBuffer nonce,
                     final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher);

        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining() + MACBYTES);
        Stodium.checkSizeMin(nonce.remaining(), NONCEBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_secretbox_xsalsa20poly1305_easy(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    @Override
    public boolean easyOpen(final @NotNull ByteBuffer dstPlain,
                            final @NotNull ByteBuffer srcCipher,
                            final @NotNull ByteBuffer nonce,
                            final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSizeMin(srcCipher.remaining(), MACBYTES);
        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining() - MACBYTES);
        Stodium.checkSizeMin(nonce.remaining(), NONCEBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        return StodiumJNI.NOERR == StodiumJNI.crypto_secretbox_xsalsa20poly1305_open_easy(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key));
    }

    @Override
    public void detached(final @NotNull ByteBuffer dstCipher,
                         final @NotNull ByteBuffer dstMac,
                         final @NotNull ByteBuffer srcPlain,
                         final @NotNull ByteBuffer nonce,
                         final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstCipher);
        Stodium.checkDestinationWritable(dstMac);

        Stodium.checkSizeMin(dstCipher.remaining(), srcPlain.remaining());
        Stodium.checkSizeMin(dstMac.remaining(), MACBYTES);
        Stodium.checkSizeMin(nonce.remaining(), NONCEBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        Stodium.checkStatus(StodiumJNI.crypto_secretbox_xsalsa20poly1305_detached(
                Stodium.ensureUsableByteBuffer(dstCipher),
                Stodium.ensureUsableByteBuffer(dstMac),
                Stodium.ensureUsableByteBuffer(srcPlain),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key)));
    }

    @Override
    public boolean detachedOpen(final @NotNull ByteBuffer dstPlain,
                                final @NotNull ByteBuffer srcCipher,
                                final @NotNull ByteBuffer srcMac,
                                final @NotNull ByteBuffer nonce,
                                final @NotNull ByteBuffer key)
            throws StodiumException {
        Stodium.checkDestinationWritable(dstPlain);

        Stodium.checkSizeMin(dstPlain.remaining(), srcCipher.remaining());
        Stodium.checkSizeMin(srcMac.remaining(), MACBYTES);
        Stodium.checkSizeMin(nonce.remaining(), NONCEBYTES);
        Stodium.checkSize(key.remaining(), KEYBYTES);

        return StodiumJNI.NOERR == StodiumJNI.crypto_secretbox_xsalsa20poly1305_open_detached(
                Stodium.ensureUsableByteBuffer(dstPlain),
                Stodium.ensureUsableByteBuffer(srcCipher),
                Stodium.ensureUsableByteBuffer(srcMac),
                Stodium.ensureUsableByteBuffer(nonce),
                Stodium.ensureUsableByteBuffer(key));
    }
}
