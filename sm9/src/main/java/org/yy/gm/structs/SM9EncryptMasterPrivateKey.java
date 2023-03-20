package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9加密主私钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:59
 */
public class SM9EncryptMasterPrivateKey extends SM9MasterPrivateKey {
    public SM9EncryptMasterPrivateKey(SM9Parameters parameters, Element g, BigInteger k) {
        super(parameters, g, false, k);
    }
}
