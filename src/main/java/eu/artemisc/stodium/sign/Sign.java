/*
 * Copyright (c) 2017 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.sign;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Sign {

    private static final @NotNull Singleton<Sign> ED25519 = new Singleton<Sign>() {
        @NotNull
        @Override
        protected Sign initialize() {
            return new Ed25519();
        }
    };

    @NotNull
    public static Sign instance() {
        return ed25519Instance();
    }

    @NotNull
    public static Sign ed25519Instance() {
        return ED25519.get();
    }

    // constants
    final int PUBLICKEYBYTES;
    final int SECRETKEYBYTES;
    final int BYTES;
    final int SEEDBYTES;
    final int STATEBYTES;

    /**
     *
     * @param pub
     * @param secret
     * @param bytes
     * @param seed
     */
    Sign(final int pub,
         final int secret,
         final int bytes,
         final int seed,
         final int state) {
        this.PUBLICKEYBYTES = pub;
        this.SECRETKEYBYTES = secret;
        this.BYTES          = bytes;
        this.SEEDBYTES      = seed;
        this.STATEBYTES     = state;
    }

    /**
     *
     * @return
     */
    public final int publicKeyBytes() {
        return PUBLICKEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int secretKeyBytes() {
        return SECRETKEYBYTES;
    }

    /**
     *
     * @return
     */
    public final int bytes() {
        return BYTES;
    }

    /**
     *
     * @return
     */
    public final int seedBytes() {
        return SEEDBYTES;
    }

    /**
     *
     * @param dstPub
     * @param dstPriv
     * @throws StodiumException
     */
    public abstract void keypair(final @NotNull ByteBuffer dstPub,
                                 final @NotNull ByteBuffer dstPriv)
            throws StodiumException;

    /**
     *
     * @param dstPub
     * @param dstPriv
     * @param seed
     * @throws StodiumException
     */
    public abstract void keypair(final @NotNull ByteBuffer dstPub,
                                 final @NotNull ByteBuffer dstPriv,
                                 final @NotNull ByteBuffer seed)
            throws StodiumException;

    /**
     *
     * @param dstSigned
     * @param srcMsg
     * @param priv
     * @throws StodiumException
     */
    public abstract void sign(final @NotNull ByteBuffer dstSigned,
                              final @NotNull ByteBuffer srcMsg,
                              final @NotNull ByteBuffer priv)
            throws StodiumException;

    /**
     *
     * @param dstMsg
     * @param srcSigned
     * @param priv
     * @return
     * @throws StodiumException
     */
    public abstract boolean open(final @NotNull ByteBuffer dstMsg,
                                 final @NotNull ByteBuffer srcSigned,
                                 final @NotNull ByteBuffer priv)
            throws StodiumException;

    /**
     *
     * @param dstSig
     * @param srcMsg
     * @param priv
     * @throws StodiumException
     */
    public abstract void signDetached(final @NotNull ByteBuffer dstSig,
                                      final @NotNull ByteBuffer srcMsg,
                                      final @NotNull ByteBuffer priv)
            throws StodiumException;

    /**
     *
     * @param srcSig
     * @param srcMsg
     * @param priv
     * @return
     * @throws StodiumException
     */
    public abstract boolean verifyDetached(final @NotNull ByteBuffer srcSig,
                                           final @NotNull ByteBuffer srcMsg,
                                           final @NotNull ByteBuffer priv)
            throws StodiumException;

    /**
     *
     * @return
     * @throws StodiumException
     */
    @NotNull
    public abstract MultipartSign init()
            throws StodiumException;
}
