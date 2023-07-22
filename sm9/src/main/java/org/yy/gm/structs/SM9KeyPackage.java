package org.yy.gm.structs;

import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9KeyParameters;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9密钥封装结果。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:10
 */
public class SM9KeyPackage {
    public byte[] K;
    /** 封装的交换密文。是G1上的一个点，可以用在KDF中计算出密钥K。*/
    public Element C;

    public SM9KeyPackage(byte[] K, Element C) {
        this.K = K;
        this.C = C;
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] temp = C.toBytes();
        bos.write(temp, 0, temp.length);
        bos.write(K, 0, K.length);
        return bos.toByteArray();
    }

    public byte[] getKey() {
        return K;
    }

    public byte[] getC() {
        // return C.toBytes();
        return SM9Utils.elementToByte(C);
    }

    public static SM9KeyPackage fromByteArray(SM9KeyParameters keyParameters, byte[] in) {
        return fromByteArray(keyParameters, in, 0, in.length);
    }

    public static SM9KeyPackage fromByteArray(SM9KeyParameters keyParameters, byte[] in, int inOff, int inLen) {
        inLen += inOff;
        Element C = keyParameters.parameters.pairing.getG1().newElementFromBytes(
                Arrays.copyOfRange(in, inOff, inOff+ SM9CurveParameters.LEN_G1_ELEMENT));
        inOff += SM9CurveParameters.LEN_G1_ELEMENT;
        byte[] K = Arrays.copyOfRange(in, inOff, inLen);
        return new SM9KeyPackage(K, C);
    }
}
