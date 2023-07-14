package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9签名主私钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:59
 */
public class SM9SignMasterPrivateKey extends SM9MasterPrivateKey {
    public SM9SignMasterPrivateKey(SM9Parameters parameters, Element g, BigInteger k) {
        super(parameters, g, true, k);
    }

    public static SM9SignMasterPrivateKey fromByteArray(SM9Parameters parameters, byte[] key) {
        return (SM9SignMasterPrivateKey) SM9MasterPrivateKey.fromByteArray(parameters, true, key);
    }
}
