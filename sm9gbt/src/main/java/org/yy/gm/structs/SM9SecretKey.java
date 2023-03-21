package org.yy.gm.structs;

import org.yy.gm.params.SM9KeyParameters;
import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9加密私钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:04
 */
public class SM9SecretKey extends SM9KeyParameters {
    public Element d;

    public SM9SecretKey(SM9Parameters parameters, Element g, Element d) {
        super(true, parameters, g);
        this.d = d;
    }
}
