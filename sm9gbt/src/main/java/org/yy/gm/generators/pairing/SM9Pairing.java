package org.yy.gm.generators.pairing;

import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.poly.PolyModField;
import it.unisa.dia.gas.plaf.jpbc.pairing.f.TypeFPairing;

/**
 * SM9 Pairing.
 *
 * @author yaoyuan
 * @since 2023/3/9 22:28
 */
public class SM9Pairing extends TypeFPairing {
    public SM9Pairing(PairingParameters curveParams) {
        super(curveParams);
    }

    public SM9Pairing(SecureRandom random, PairingParameters curveParams) {
        super(random, curveParams);
    }

    @Override
    protected void initMap() {
        BigInteger t = curveParams.getBigInteger("t");
        BigInteger a = t.multiply(BigInteger.valueOf(6)).add(BigInteger.valueOf(2));
        pairingMap = new SM9RatePairingMap(this, a);
    }

    public BigInteger getN() {
        return this.r;
    }

    protected Field getFq2() {
        return Fq2;
    }

    protected PolyModField getFq12()
    {
        return Fq12;
    }

    protected BigInteger getQ() {
        return q;
    }

    protected Element getNegAlphaInv() {
        return negAlphaInv;
    }

    public PairingParameters getPairingParameters() {
        return curveParams;
    }
}
