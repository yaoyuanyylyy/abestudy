package org.yy.gm.test.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.yy.gm.SM9LogUtils;
import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9KeyParameters;
import org.yy.gm.params.SM9SignParameters;
import org.yy.gm.params.SM9VerifyParameters;
import org.yy.gm.structs.SM9Signature;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;

/**
 * SM9签名验签。
 *
 * @author yaoyuan
 * @since 2023/3/10 20:07
 */
public class SM9SignerTest implements Signer {
    public static BigInteger r = BigInteger.ONE;
    private SM9KeyParameters key;
    private Pairing pairing;
    private final ByteArrayOutputStream bos = new ByteArrayOutputStream();

    public SM9SignerTest() {
    }

    @Override
    public void init(boolean forSigning, CipherParameters cipherParameters) {
        if(forSigning) {
            if(!(cipherParameters instanceof SM9SignParameters))
                throw new IllegalArgumentException("SM9SignParameters are required for sign.");
        } else if(!(cipherParameters instanceof SM9VerifyParameters))
            throw new IllegalArgumentException("SM9VerifyParameters are required for verify sign.");

        key = (SM9KeyParameters) cipherParameters;
        pairing = key.parameters.pairing;
        bos.reset();
    }

    @Override
    public void update(byte b) {
        bos.write(b);
    }

    @Override
    public void update(byte[] in, int off, int len) {
        bos.write(in, off, len);
    }

    @Override
    public byte[] generateSignature() throws CryptoException, DataLengthException {
        if(key==null)
            throw new IllegalStateException("SM9 singer not initialized");

        SM9SignParameters signParameters = (SM9SignParameters)key;

        byte[] hash = this.bos.toByteArray();

        BigInteger l, h;

        //Step1 : g = e(P1, Ppub-s)
        SM9LogUtils.showMsg("群GT中的元素 g:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(signParameters.g)));

        do {
            //Step2: generate r
            // BigInteger r = key.parameters.pairing.getZr().newRandomElement().getImmutable().toBigInteger();
            SM9LogUtils.showMsg("产生随机数 r:");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.bigIntegerToBytes(r, SM9CurveParameters.LEN_N)));


            //Step3 : calculate w=g^r
            Element w = signParameters.g.pow(r);
            SM9LogUtils.showMsg("群GT中的元素 w:");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(w)));

            //Step4 : calculate h=H2(M||w,N)
            h = SM9Utils.H2(hash, w, key.parameters.N);
            SM9LogUtils.showMsg("h:");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.bigIntegerToBytes(h)));

            //Step5 : l=(r-h)mod N
            l = r.subtract(h).mod(key.parameters.N);
            SM9LogUtils.showMsg("l:");
            SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.bigIntegerToBytes(l)));
        } while(l.equals(BigInteger.ZERO));

        //Step6 : S=[l]dSA=(xS,yS)
        Element S = signParameters.signPrivateKey.Q.mul(l).getImmutable();
        SM9LogUtils.showMsg("群G1中的元素 s:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(S.toBytes()));

        //Step7 : signature=(h,s)
        return new SM9Signature(h, S).toByteArray();
    }

    @Override
    public boolean verifySignature(byte[] in) {
        if(key==null)
            throw new IllegalStateException("SM9 singer not initialized");

        SM9VerifyParameters verifyParameters = (SM9VerifyParameters)key;
        SM9Signature signature = SM9Signature.fromByteArray(key, in, 0, in.length);

        byte[] hash = this.bos.toByteArray();

        // Step1 : check if h in the range [1, N-1]
        if(!SM9Utils.isInN(signature.h, key.parameters.N))
            return false;

        // Step2 : check if S is on G1
        if(!((CurveElement)signature.S).isValid())
            return false;

        // Step3 : g = e(P1, Ppub-s)
        Element g = pairing.pairing(key.parameters.P1, verifyParameters.signMasterPublicKey.Q);
        SM9LogUtils.showMsg("群GT中的元素 g:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(g)));

        // Step4 : calculate t=g^h
        Element t = g.pow(signature.h);
        SM9LogUtils.showMsg("群GT中的元素 t:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(t)));

        // Step5 : calculate h1=H1(IDA||hid,N)
        // Step6 : P=[h1]P2+Ppubs
        Element P = SM9Utils.preQ(verifyParameters.signMasterPublicKey, verifyParameters.hid, verifyParameters.signerId);
        SM9LogUtils.showMsg("群G2中的元素 P:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.G2ElementToByte(P)));

        // Step7 : u=e(S,P)
        Element u = pairing.pairing(signature.S, P);
        SM9LogUtils.showMsg("群GT中的元素 u:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(u)));

        // Step8 : w=u*t
        Element w2 = u.mul(t);
        SM9LogUtils.showMsg("群GT中的元素 w':");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.GTFiniteElementToByte(w2)));

        // Step9 : h2=H2(M||w,N)
        BigInteger h2 = SM9Utils.H2(hash, w2, key.parameters.N);
        SM9LogUtils.showMsg("h2:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(SM9Utils.bigIntegerToBytes(h2)));
        if(h2.equals(signature.h))
            SM9LogUtils.showMsg("h2 = h, 验证通过! \n");

        return h2.equals(signature.h);
    }

    @Override
    public void reset() {
        bos.reset();
    }
}
