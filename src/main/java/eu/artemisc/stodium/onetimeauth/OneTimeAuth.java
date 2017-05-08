/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.onetimeauth;

import org.jetbrains.annotations.NotNull;

import eu.artemisc.stodium.Singleton;
import eu.artemisc.stodium.auth.Auth;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class OneTimeAuth
        extends Auth {

    private static final @NotNull Singleton<OneTimeAuth> POLY1305 = new Singleton<OneTimeAuth>() {
        @NotNull
        @Override
        protected OneTimeAuth initialize() {
            return new Poly1305();
        }
    };

    @NotNull
    public static OneTimeAuth instance() {
        return poly1305Instance();
    }

    @NotNull
    public static OneTimeAuth poly1305Instance() {
        return POLY1305.get();
    }

    /**
     * @param bytes
     * @param key
     * @param state
     */
    OneTimeAuth(final int bytes,
                final int key,
                final int state) {
        super(bytes, key, state);
    }
}
