/*
 * Copyright (c) 2016 Project ArteMisc
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package eu.artemisc.stodium.core;

import eu.artemisc.stodium.exceptions.ConstraintViolationException;
import eu.artemisc.stodium.exceptions.StodiumException;

/**
 * @author Jan van de Molengraft [jan@artemisc.eu]
 */
public class HChacha20 {

    // constants
    //public static final int INPUTBYTES  = Sodium.crypto_core_hchacha20_inputbytes();
    //public static final int OUTPUTBYTES = Sodium.crypto_core_hchacha20_outputbytes();
    //public static final int CONSTBYTES  = Sodium.crypto_core_hchacha20_constbytes();
    //public static final int KEYBYTES    = Sodium.crypto_core_hchacha20_keybytes();

    /**
     *
     * @param dst
     * @param src
     * @param key
     * @param constant
     * @throws ConstraintViolationException
     * @throws StodiumException
     */
    //public void hchacha20(@NonNull final byte[] dst,
    //                      @NonNull final byte[] src,
    //                      @NonNull final byte[] key,
    //                      @Nullable final byte[] constant)
    //        throws StodiumException {
    //    if (constant != null) {
    //        Stodium.checkSize(constant.length, CONSTBYTES, "HChacha20.CONSTBYTES");
    //    }
    //    Stodium.checkSize(dst.length, OUTPUTBYTES, "HChacha20.OUTPUTBYTES");
    //    Stodium.checkSize(src.length, INPUTBYTES, "HChacha20.INPUTBYTES");
    //    Stodium.checkSize(key.length, KEYBYTES, "HChacha20.KEYBYTES");
    //    Stodium.checkStatus(Sodium.crypto_core_hsalsa20(
    //            dst, src, key, constant));
    //}

}
