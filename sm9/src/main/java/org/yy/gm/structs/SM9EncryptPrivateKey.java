package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9加密私钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:04
 */
public class SM9EncryptPrivateKey extends SM9PrivateKey {
    public SM9EncryptPrivateKey(SM9Parameters parameters, Element g, Element Q) {
        super(parameters, g, false, Q);
    }

    public static SM9EncryptPrivateKey fromByteArray(SM9Parameters parameters, byte[] key) {
        return (SM9EncryptPrivateKey) SM9PrivateKey.fromByteArray(true, parameters, false, key);
    }
}
