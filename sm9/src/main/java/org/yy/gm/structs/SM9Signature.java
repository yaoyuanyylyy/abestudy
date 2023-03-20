package org.yy.gm.structs;

import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9KeyParameters;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9签名值。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:54
 */
public class SM9Signature {
    public BigInteger h;
    public Element S;

    public SM9Signature(BigInteger h, Element S) {
        this.h = h;
        this.S = S;
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        byte[] temp =  SM9Utils.bigIntegerToBytes(h, SM9CurveParameters.LEN_N);
        bos.write(temp, 0, temp.length);

        temp = S.toBytes();
        bos.write(temp, 0, temp.length);

        return bos.toByteArray();
    }

    public static SM9Signature fromByteArray(SM9KeyParameters keyParameters, byte[] in) {
        return fromByteArray(keyParameters, in, 0, in.length);
    }

    public static SM9Signature fromByteArray(SM9KeyParameters keyParameters, byte[] in, int off, int len) {
        len += off;
        BigInteger h = new BigInteger(1, Arrays.copyOfRange(in, off, SM9CurveParameters.LEN_N));
        off += SM9CurveParameters.LEN_N;

        Element S = keyParameters.parameters.pairing.getG1().newElementFromBytes(Arrays.copyOfRange(in, off, len));
        return new SM9Signature(h, S);
    }
}
