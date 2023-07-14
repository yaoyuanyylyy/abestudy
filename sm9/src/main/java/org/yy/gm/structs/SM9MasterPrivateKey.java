package org.yy.gm.structs;

import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9CurveParameters;
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

    public byte[] toByteArray() {
        return SM9Utils.bigIntegerToBytes(k, SM9CurveParameters.LEN_N);
    }

    public static SM9MasterPrivateKey fromByteArray(SM9Parameters parameters, boolean isSignKey, byte[] key) {
        BigInteger k = new BigInteger(1, key);
        Element Q = isSignKey ? parameters.P2.mul(k).getImmutable() : parameters.P1.mul(k).getImmutable();
        Element g = SM9Utils.preE(parameters, Q, isSignKey);
        return isSignKey ? new SM9SignMasterPrivateKey(parameters, g, k) : new SM9EncryptMasterPrivateKey(parameters, g, k);
    }
}
