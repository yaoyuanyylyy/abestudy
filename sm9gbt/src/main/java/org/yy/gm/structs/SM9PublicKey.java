package org.yy.gm.structs;

import org.yy.gm.params.SM9KeyParameters;
import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9主公钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:57
 */
public class SM9PublicKey extends SM9KeyParameters {
    public Element Q;

    public SM9PublicKey(SM9Parameters parameters, Element g, Element Q) {
        super(false, parameters, g);
        this.Q = Q;
    }
}
