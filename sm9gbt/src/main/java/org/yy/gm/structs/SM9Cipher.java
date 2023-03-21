package org.yy.gm.structs;

import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9KeyParameters;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9密文。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:04
 */
public class SM9Cipher {
    public byte enType = 0;
    public Element C1;
    public byte[] C2;
    public byte[] C3;

    public SM9Cipher(byte enType, Element C1, byte[] C2, byte[] C3) {
        this.enType = enType;
        this.C1 = C1;
        this.C2 = C2;
        this.C3 = C3;
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(enType);
        byte[] temp = C1.toBytes();
        bos.write(temp, 0, temp.length);
        bos.write(C3, 0, C3.length);
        bos.write(C2, 0, C2.length);
        return bos.toByteArray();
    }

    public static SM9Cipher fromByteArray(SM9KeyParameters keyParameters, byte[] in) {
        return fromByteArray(keyParameters, in, 0, in.length);
    }

    public static SM9Cipher fromByteArray(SM9KeyParameters keyParameters, byte[] in, int inOff, int inLen) {
        inLen += inOff;
        byte enType = in[0];
        inOff += 1;
        Element C1 = keyParameters.parameters.pairing.getG1().newElementFromBytes(Arrays.copyOfRange(in, inOff, inOff + SM9CurveParameters.LEN_G1_ELEMENT));
        inOff += SM9CurveParameters.LEN_G1_ELEMENT;
        int digestLen = SM9Utils.getDigestLength();
        byte[] C3 = Arrays.copyOfRange(in, inOff, inOff + digestLen);
        inOff += digestLen;
        byte[] C2 = Arrays.copyOfRange(in, inOff, inLen);
        return new SM9Cipher(enType, C1, C2, C3);
    }
}
