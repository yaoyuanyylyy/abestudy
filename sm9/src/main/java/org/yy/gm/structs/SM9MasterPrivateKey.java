package org.yy.gm.structs;

import org.yy.gm.params.SM9KeyParameters;
import org.yy.gm.params.SM9Parameters;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9主私钥。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:59
 */
public class SM9MasterPrivateKey extends SM9KeyParameters {
    protected BigInteger k;

    public SM9MasterPrivateKey(SM9Parameters parameters, Element g, boolean isSignKey, BigInteger k) {
        super(true, parameters, g, isSignKey);
        this.k = k;
    }

    public BigInteger getKey() {
        return k;
    }
}
