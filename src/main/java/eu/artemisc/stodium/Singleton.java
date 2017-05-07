/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Singleton implements a simple mechanism to support lazy initialization of
 * singleton classes.
 *
 * @param <T> the singleton instance's type.
 *
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public abstract class Singleton<T> {
    /**
     *
     */
    private @Nullable T instance;

    /**
     *
     * @return
     */
    @NotNull
    protected abstract T initialize();

    /**
     *
     * @return
     */
    @NotNull
    public final T get() {
        synchronized (this) {
            if (instance == null) {
                instance = initialize();
            }
            return instance;
        }
    }
}