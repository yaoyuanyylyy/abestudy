package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9公钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:57
 */
public class SM9PublicKey extends SM9ElementKey {
    public SM9PublicKey(SM9Parameters parameters, Element g, boolean isSignKey, Element Q) {
        super(false, parameters, g, isSignKey, Q);
    }

    public static SM9PublicKey fromByteArray(SM9Parameters parameters, boolean isSignKey, byte[] key) {
        return (SM9PublicKey) SM9ElementKey.publicKeyFromByteArray(parameters, isSignKey, key);
    }
}
