package org.yy.gm.test.engines;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.yy.gm.SM9LogUtils;
import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9KDMParameters;
import org.yy.gm.params.SM9KEMEngineParameters;
import org.yy.gm.params.SM9KEMParameters;
import org.yy.gm.structs.SM9KeyPackage;

import java.math.BigInteger;
import java.util.Arrays;

import it.unisa.dia.gas.crypto.jpbc.kem.PairingKeyEncapsulationMechanism;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;

/**
 * SM9密钥封装和解封。
 *
 * @author yaoyuan
 * @since 2023/3/10 1:28
 */
public class SM9KEMEngineTest extends PairingKeyEncapsulationMechanism {
    public static BigInteger r = BigInteger.ONE;

    @Override
    public void initialize() {
        if(forEncryption) {
            if(!(key instanceof SM9KEMParameters))
                throw new IllegalArgumentException("SM9KEMParameters are required for key encapsulate.");
        } else if(!(key instanceof SM9KDMParameters))
            throw new IllegalArgumentException("SM9KDMParameters are required for key decapsulate.");

        SM9KEMEngineParameters engineParameters = (SM9KEMEngineParameters) key;
        pairing = engineParameters.parameters.pairing;
        keyBytes = engineParameters.keyByteLen;
    }

    @Override
    public byte[] process(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        return forEncryption ? keyEncapsulate().toByteArray() : keyDecapsulate(in, inOff, inLen);
    }

    protected SM9KeyPackage keyEncapsulate() {
        SM9KEMParameters kemParameters = (SM9KEMParameters) key;

        //Step1 : QB=[H1(IDB||hid, N)]P1+Ppub-e
        Element QB = SM9Utils.preQ(kemParameters.encryptMasterPublicKey, kemParameters.hid, kemParameters.id);
        SM9LogUtils.showMsg("QB:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(QB.toBytes()));

        byte[] K;
        Element C;

        do {
            //Step2: generate r
            // BigInteger r = pairing.getZr().newRandomElement().getImmutable().toBigInteger();
            SM9LogUtils.showMsg("r:");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.bigIntegerToBytes(r, SM9CurveParameters.LEN_N)));

            //Step3 : C=[r]QB
            C = QB.mul(r).getImmutable();
            SM9LogUtils.showMsg("C");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(C.toBytes()));

            //Step4 : g=e(Ppub-e, P2)
            SM9LogUtils.showMsg("g:");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(kemParameters.g)));

            //Step5 : calculate w=g^r
            Element w = kemParameters.g.pow(r);
            SM9LogUtils.showMsg("w:");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(w)));

            //Step6 : K = KDF(C || w || IDB, klen)
            K = SM9Utils.KDF(C, w, kemParameters.id, keyBytes);

        } while (SM9Utils.isAllZero(K));

        SM9LogUtils.showMsg("K:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(K));

        //Step7 : output (K,C)
        return new SM9KeyPackage(K, C);
    }

    protected byte[] keyDecapsulate(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        SM9KDMParameters kdmParameters = (SM9KDMParameters)key;

        Element C = pairing.getG1().newElementFromBytes(Arrays.copyOfRange(in, inOff, inOff+inLen));

        if(!((CurveElement)C).isValid())
            throw new InvalidCipherTextException("C is not on G1");

        //Step2 : calculate w=e(C,de)
        Element w = pairing.pairing(C, kdmParameters.encryptPrivateKey.Q);
        SM9LogUtils.showMsg("w':");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(w)));

        //Step3 : K = KDF(C || w || IDB, klen)
        byte[] K = SM9Utils.KDF(C, w, kdmParameters.id, keyBytes);

        if(SM9Utils.isAllZero(K))
            throw new InvalidCipherTextException("K is all zero");

        SM9LogUtils.showMsg("K':");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(K));

        //Step4 : output K
        return K;
    }
}
