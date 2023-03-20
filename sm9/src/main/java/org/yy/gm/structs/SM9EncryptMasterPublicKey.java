package org.yy.gm.structs;

import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9加密主公钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:00
 */
public class SM9EncryptMasterPublicKey extends SM9MasterPublicKey {
    public SM9EncryptMasterPublicKey(SM9Parameters parameters, Element g, Element Q) {
        super(parameters, g, false, Q);
    }
}
