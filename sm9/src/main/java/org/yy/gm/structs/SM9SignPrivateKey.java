package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9签名私钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:03
 */
public class SM9SignPrivateKey extends SM9PrivateKey {
    public SM9SignPrivateKey(SM9Parameters parameters, Element g, Element Q) {
        super(parameters, g, true, Q);
    }
}
