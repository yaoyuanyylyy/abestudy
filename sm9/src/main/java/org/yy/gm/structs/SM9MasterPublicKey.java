package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9主公钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:00
 */
public class SM9MasterPublicKey extends SM9PublicKey {
    public SM9MasterPublicKey(SM9Parameters parameters, Element g, boolean isSignKey, Element Q) {
        super(parameters, g, isSignKey, Q);
    }

    public static SM9MasterPublicKey fromByteArray(SM9Parameters parameters, boolean isSignKey, byte[] key) {
        return (SM9MasterPublicKey) SM9PublicKey.fromByteArray(parameters, isSignKey, key);
    }
}
