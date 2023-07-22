package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9用户私钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:58
 */
public class SM9PrivateKey extends SM9ElementKey {
    public SM9PrivateKey(SM9Parameters parameters, Element g, boolean isSignKey, Element Q) {
        super(true, parameters, g, isSignKey, Q);
    }

    public static SM9PrivateKey fromByteArray(SM9MasterPublicKey masterPublicKey, boolean isSignKey, byte[] key) {
        return (SM9PrivateKey) SM9ElementKey.privateKeyFromByteArray(masterPublicKey, isSignKey, key);
    }
}
