/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.pwhash;

import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class PwHash {

    private static final @NotNull Singleton<PwHash> ARGON2I = new Singleton<PwHash>() {
        @NotNull
        @Override
        protected PwHash initialize() {
            return new Argon2i();
        }
    };

    private static final @NotNull Singleton<PwHash> SCRYPT = new Singleton<PwHash>() {
        @NotNull
        @Override
        protected PwHash initialize() {
            return new Scrypt();
        }
    };

    @NotNull
    public static PwHash instance() {
        return argon2iInstance();
    }

    @NotNull
    public static PwHash argon2iInstance() {
        return ARGON2I.get();
    }

    @NotNull
    public static PwHash scryptInstance() {
        return SCRYPT.get();
    }

    // constants
    final          long   BYTES_MIN;
    final          long   BYTES_MAX;
    final          long   PASSWD_MIN;
    final          long   PASSWD_MAX;
    final          int    SALTBYTES;
    final          int    STRBYTES;
    final @NotNull String STRPREFIX;
    final          long   OPSLIMIT_MIN;
    final          long   OPSLIMIT_MAX;
    final          long   MEMLIMIT_MIN;
    final          long   MEMLIMIT_MAX;
    final          long   OPSLIMIT_INTERACTIVE;
    final          long   MEMLIMIT_INTERACTIVE;
    final          long   OPSLIMIT_MODERATE;
    final          long   MEMLIMIT_MODERATE;
    final          long   OPSLIMIT_SENSITIVE;
    final          long   MEMLIMIT_SENSITIVE;

    /**
     *
     * @param bytesMin
     * @param bytesMax
     * @param pwMin
     * @param pwMax
     * @param salt
     * @param str
     * @param prefix
     * @param opsMin
     * @param opsMax
     * @param memMin
     * @param memMax
     * @param opsInteractive
     * @param memInteractive
     * @param opsModerate
     * @param memModerate
     * @param opsSensitive
     * @param memSensitive
     */
    PwHash(final          long   bytesMin,
           final          long   bytesMax,
           final          long   pwMin,
           final          long   pwMax,
           final          int    salt,
           final          int    str,
           final @NotNull String prefix,
           final          long   opsMin,
           final          long   opsMax,
           final          long   memMin,
           final          long   memMax,
           final          long   opsInteractive,
           final          long   memInteractive,
           final          long   opsModerate,
           final          long   memModerate,
           final          long   opsSensitive,
           final          long   memSensitive) {
        this.BYTES_MIN            = bytesMin;
        this.BYTES_MAX            = bytesMax;
        this.PASSWD_MIN           = pwMin;
        this.PASSWD_MAX           = pwMax;
        this.SALTBYTES            = salt;
        this.STRBYTES             = str;
        this.STRPREFIX            = prefix;
        this.OPSLIMIT_MIN         = opsMin;
        this.OPSLIMIT_MAX         = opsMax;
        this.MEMLIMIT_MIN         = memMin;
        this.MEMLIMIT_MAX         = memMax;
        this.OPSLIMIT_INTERACTIVE = opsInteractive;
        this.MEMLIMIT_INTERACTIVE = memInteractive;
        this.OPSLIMIT_MODERATE    = opsModerate;
        this.MEMLIMIT_MODERATE    = memModerate;
        this.OPSLIMIT_SENSITIVE   = opsSensitive;
        this.MEMLIMIT_SENSITIVE   = memSensitive;
    }

    /**
     *
     * @return
     */
    public final long bytesMin() {
        return BYTES_MIN;
    }

    /**
     *
     * @return
     */
    public final long bytesMax() {
        return BYTES_MAX;
    }

    /**
     *
     * @return
     */
    public final long passwdMin() {
        return PASSWD_MIN;
    }

    /**
     *
     * @return
     */
    public final long passwdMax() {
        return PASSWD_MAX;
    }

    /**
     *
     * @return
     */
    public final int saltBytes() {
        return SALTBYTES;
    }

    /**
     *
     * @return
     */
    public final int strBytes() {
        return STRBYTES;
    }

    /**
     *
     * @return
     */
    @NotNull
    public final String strPrefix() {
        return STRPREFIX;
    }

    /**
     *
     * @return
     */
    public final long opslimitMin() {
        return OPSLIMIT_MIN;
    }

    /**
     *
     * @return
     */
    public final long opslimitMax() {
        return OPSLIMIT_MAX;
    }

    /**
     *
     * @return
     */
    public final long memlimitMin() {
        return MEMLIMIT_MIN;
    }

    /**
     *
     * @return
     */
    public final long memlimitMax() {
        return MEMLIMIT_MAX;
    }

    /**
     *
     * @return
     */
    public final long opslimitInteractive() {
        return OPSLIMIT_INTERACTIVE;
    }

    /**
     *
     * @return
     */
    public final long memlimitInteractive() {
        return MEMLIMIT_INTERACTIVE;
    }

    /**
     *
     * @return
     */
    public final long opslimitModerate() {
        return OPSLIMIT_MODERATE;
    }

    /**
     *
     * @return
     */
    public final long memlimitModerate() {
        return MEMLIMIT_MODERATE;
    }

    /**
     *
     * @return
     */
    public final long opslimitSensitive() {
        return OPSLIMIT_SENSITIVE;
    }

    /**
     *
     * @return
     */
    public final long memlimitSensitive() {
        return MEMLIMIT_SENSITIVE;
    }

    /**
     *
     * @param dstHash
     * @param srcPw
     * @param srcSalt
     * @throws StodiumException
     */
    public final void hash(final @NotNull ByteBuffer dstHash,
                           final @NotNull ByteBuffer srcPw,
                           final @NotNull ByteBuffer srcSalt)
            throws StodiumException {
        hash(dstHash, srcPw, srcSalt, OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE);
    }

    /**
     *
     * @param dstHash
     * @param srcPw
     * @param srcSalt
     * @param opsLimit
     * @param memLimit
     * @throws StodiumException
     */
    public abstract void hash(final @NotNull ByteBuffer dstHash,
                              final @NotNull ByteBuffer srcPw,
                              final @NotNull ByteBuffer srcSalt,
                              final          long       opsLimit,
                              final          long       memLimit)
            throws StodiumException;

    /**
     *
     * @param srcPw
     * @param opsLimit
     * @param memLimit
     * @return
     * @throws StodiumException
     */
    @NotNull
    public final String strHash(final @NotNull ByteBuffer srcPw,
                                final          long       opsLimit,
                                final          long       memLimit)
            throws StodiumException {
        final byte[] dst;
        dst = new byte[STRBYTES];

        strHash(ByteBuffer.wrap(dst), srcPw, opsLimit, memLimit);

        return new String(dst);
    }

    /**
     *
     * @param dstString
     * @param srcPw
     * @param opsLimit
     * @param memLimit
     * @throws StodiumException
     */
    public abstract void strHash(final @NotNull ByteBuffer dstString,
                                 final @NotNull ByteBuffer srcPw,
                                 final          long       opsLimit,
                                 final          long       memLimit)
            throws StodiumException;

    /**
     *
     * @param str
     * @param pw
     * @return
     */
    public abstract boolean strVerify(final @NotNull ByteBuffer str,
                                      final @NotNull ByteBuffer pw)
            throws StodiumException;

    /**
     *
     * @param str
     * @param pw
     * @return
     */
    public final boolean strVerify(final @NotNull String     str,
                                   final @NotNull ByteBuffer pw)
            throws StodiumException {
        final ByteBuffer buff;
        buff = ByteBuffer.wrap(str.getBytes());
        return strVerify(buff, pw);
    }
}
