package org.yy.gm.params;

import org.bouncycastle.crypto.CipherParameters;
import org.yy.gm.generators.pairing.SM9Pairing;

import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9参数。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:52
 */
public class SM9Parameters implements CipherParameters {
    public SecureRandom random;
    public SM9Pairing pairing;
    public Element P1;
    public Element P2;
    public BigInteger N;

    public SM9Parameters(SecureRandom random, SM9Pairing pairing, Element P1, Element P2) {
        this.random = random;
        this.pairing = pairing;
        this.P1 = P1;
        this.P2 = P2;
        this.N = pairing.getN();
    }

}
