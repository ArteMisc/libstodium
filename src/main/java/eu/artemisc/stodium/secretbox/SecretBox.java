package eu.artemisc.stodium.secretbox;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class SecretBox {

    private static final @NotNull Singleton<SecretBox> CURVE_XSALSA = new Singleton<SecretBox>() {
        @NotNull
        @Override
        protected SecretBox initialize() {
            return new XSalsa20Poly1305();
        }
    };

    private static final @NotNull Singleton<SecretBox> CURVE_XCHACHA = new Singleton<SecretBox>() {
        @NotNull
        @Override
        protected SecretBox initialize() {
            return new XChacha20Poly1305();
        }
    };

    @NotNull
    public static SecretBox instance() {
        return xsalsa20poly1305Instance();
    }

    @NotNull
    public static SecretBox xsalsa20poly1305Instance() {
        return CURVE_XSALSA.get();
    }

    @NotNull
    public static SecretBox xchacha20poly1305Instance() {
        return CURVE_XCHACHA.get();
    }

    // constants
    final int KEYBYTES;
    final int MACBYTES;
    final int NONCEBYTES;

    /**
     *
     * @param key
     * @param mac
     * @param nonce
     */
    SecretBox(final int key,
              final int mac,
              final int nonce) {
        this.KEYBYTES   = key;
        this.MACBYTES   = mac;
        this.NONCEBYTES = nonce;
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
     * @return
     */
    public final int macBytes() {
        return MACBYTES;
    }

    /**
     *
     * @return
     */
    public final int nonceBytes() {
        return NONCEBYTES;
    }

    /**
     *
     * @param dstCipher
     * @param srcPlain
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public abstract void easy(final @NotNull ByteBuffer dstCipher,
                              final @NotNull ByteBuffer srcPlain,
                              final @NotNull ByteBuffer nonce,
                              final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param nonce
     * @param key
     * @return
     * @throws StodiumException
     */
    public abstract boolean easyOpen(final @NotNull ByteBuffer dstPlain,
                                     final @NotNull ByteBuffer srcCipher,
                                     final @NotNull ByteBuffer nonce,
                                     final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param dstCipher
     * @param dstMac
     * @param srcPlain
     * @param nonce
     * @param key
     * @throws StodiumException
     */
    public abstract void detached(final @NotNull ByteBuffer dstCipher,
                                  final @NotNull ByteBuffer dstMac,
                                  final @NotNull ByteBuffer srcPlain,
                                  final @NotNull ByteBuffer nonce,
                                  final @NotNull ByteBuffer key)
            throws StodiumException;

    /**
     *
     * @param dstPlain
     * @param srcCipher
     * @param srcMac
     * @param nonce
     * @param key
     * @return
     * @throws StodiumException
     */
    public abstract boolean detachedOpen(final @NotNull ByteBuffer dstPlain,
                                         final @NotNull ByteBuffer srcCipher,
                                         final @NotNull ByteBuffer srcMac,
                                         final @NotNull ByteBuffer nonce,
                                         final @NotNull ByteBuffer key)
            throws StodiumException;
}
