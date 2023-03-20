package org.yy.gm.engines;

import org.bouncycastle.crypto.CryptoException;
import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9KeyExchangeInitParameters;
import org.yy.gm.params.SM9KeyExchangeParameters;
import org.yy.gm.structs.SM9EncryptMasterKeyPair;
import org.yy.gm.structs.SM9EncryptMasterPrivateKey;
import org.yy.gm.structs.SM9EncryptMasterPublicKey;
import org.yy.gm.structs.SM9KeyAgreement;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveElement;

/**
 * SM9密钥协商。
 * <p>
 * 《GBT 38635.2-2020 信息安全技术 SM9标识密码算法 第2部分：算法》的密钥协商中hid取0x03，
 * 以前的GMT标准为0x02，这里遵循GBT标准。
 *
 * @author yaoyuan
 * @since 2023/3/10 23:00
 */
public class SM9KeyExchange {

    public SM9EncryptMasterKeyPair init(SM9KeyExchangeInitParameters keyExchangeInitParameters) {
        //Step1 : QB =[H1(IDB||hid, N)]P1 +Ppub-e or QA = [H1(IDA || hid, N)]P1 + Ppub-e
        Element QB = SM9Utils.preQ(keyExchangeInitParameters.encryptMasterPublicKey, keyExchangeInitParameters.hid, keyExchangeInitParameters.peerId);

        //Step2: generate r
        BigInteger r = keyExchangeInitParameters.parameters.pairing.getZr().newRandomElement().getImmutable().toBigInteger();

        //Step3 : RA = [rA]QB or RB= [rB]QA
        Element R = QB.mul(r).getImmutable();

        // g1 for sponsor or g2 for responder. Calculate it here to save some time
        Element g = keyExchangeInitParameters.encryptMasterPublicKey.g.pow(r).getImmutable();

        return new SM9EncryptMasterKeyPair(
                new SM9EncryptMasterPublicKey(keyExchangeInitParameters.parameters, g, R),
                new SM9EncryptMasterPrivateKey(keyExchangeInitParameters.parameters, g, r)
        );
    }

    public SM9KeyAgreement calculateKey(SM9KeyExchangeParameters params) throws CryptoException {
        //check R is on G1
        if (!((CurveElement) params.peerTempPublicKey.Q).isValid())
            throw new CryptoException("R is not on G1");

        //StepA5_B4
        Element g1, g2;
        Element gTemp2 = params.parameters.pairing.pairing(params.peerTempPublicKey.Q, params.myPrivateKey.Q).getImmutable();
        if (params.isSponsor) {
            g1 = params.myTempPublicKey.g;
            g2 = gTemp2.duplicate();
        } else {
            g1 = gTemp2.duplicate();
            g2 = params.myTempPublicKey.g;
        }
        Element g3 = gTemp2.pow(params.myTempPrivateKey.getKey());

        //Step6 : S1 or SB
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] temp;
        if (params.isSponsor) {
            temp = params.myId.getBytes();
            bos.write(temp, 0, temp.length);
            temp = params.peerId.getBytes();
            bos.write(temp, 0, temp.length);
            temp = params.myTempPublicKey.Q.toBytes();
            bos.write(temp, 0, temp.length);
            temp = params.peerTempPublicKey.Q.toBytes();
            bos.write(temp, 0, temp.length);
        } else {
            temp = params.peerId.getBytes();
            bos.write(temp, 0, temp.length);
            temp = params.myId.getBytes();
            bos.write(temp, 0, temp.length);
            temp = params.peerTempPublicKey.Q.toBytes();
            bos.write(temp, 0, temp.length);
            temp = params.myTempPublicKey.Q.toBytes();
            bos.write(temp, 0, temp.length);
        }
        byte[] bIDR = bos.toByteArray();

        bos.reset();
        temp = SM9Utils.GTFiniteElementToByte(g2);
        bos.write(temp, 0, temp.length);
        temp = SM9Utils.GTFiniteElementToByte(g3);
        bos.write(temp, 0, temp.length);
        byte[] bG2G3 = bos.toByteArray();

        byte[] bG1 = SM9Utils.GTFiniteElementToByte(g1);

        bos.reset();
        bos.write(bG2G3, 0, bG2G3.length);
        bos.write(bIDR, 0, bIDR.length);
        byte[] bHashIDRG2G3 = SM9Utils.Hash(bos.toByteArray());

        //SB1
        bos.reset();
        bos.write(0x82);
        bos.write(bG1, 0, bG1.length);
        bos.write(bHashIDRG2G3, 0, bHashIDRG2G3.length);
        byte[] SB1 = SM9Utils.Hash(bos.toByteArray());

        //StepA8_B7 : SA or S2
        bos.reset();
        bos.write(0x83);
        bos.write(bG1, 0, bG1.length);
        bos.write(bHashIDRG2G3, 0, bHashIDRG2G3.length);
        byte[] SA2 = SM9Utils.Hash(bos.toByteArray());

        //StepA7_B5 : SKA or SKB
        bos.reset();
        bos.write(bIDR, 0, bIDR.length);
        bos.write(bG1, 0, bG1.length);
        bos.write(bG2G3, 0, bG2G3.length);
        byte[] SK = SM9Utils.KDF(bos.toByteArray(), params.keyByteLen);

        return new SM9KeyAgreement(SK, SA2, SB1);
    }
}
