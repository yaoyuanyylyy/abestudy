package org.yy.gm.params;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

/**
 * SM9曲线参数。
 * <p>
 * 这里的参数都是SM9椭圆曲线相关的参数，一般都是固定不变的。
 * <p>
 * Fq中的两个元素a和b，它们定义椭圆曲线Fq的方程: y^2 = x^3 + ax + b.
 * <p>
 * SM9曲线中a=0, b=5，所以曲线方程为: y^2 = x^3 + b
 *
 * @author yaoyuan
 * @since 2023/3/9 21:27
 */
public class SM9CurveParameters {
    /** 阶N的字节长度 */
    public static final int LEN_N = 32;
    /** 群G1上的点的字节长度 */
    public static final int LEN_G1_ELEMENT = 64;
    /** 群G2上的点的字节长度 */
    public static final int LEN_G2_ELEMENT = 128;

    /**
     * 参数t: 可以用来确定 基域特征q，曲线阶N，Frobenius映射的迹tr.
     * 基域特征 q(t) = 36t^4 + 36t^3 + 24t^2 + 6t + 1
     * 曲线阶 N(t) = 36t^4 + 36t^3 + 18t^2 + 6t + 1
     */
    public static final BigInteger t = new BigInteger("600000000058F98A", 16);

    /** 曲线方程参数。 */
    public static final BigInteger b = BigInteger.valueOf(5);

    /** 基域特征: 椭圆曲线基域Fq的参数 */
    public static final BigInteger q = new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16);

    /** 循环群G1、G2和GT的阶；在PBC中标记为r */
    public static final BigInteger N = new BigInteger("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25", 16);

    /** TypeF类型的椭圆曲线参数: beta */
    public static final BigInteger beta = new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457B", 16);

    /** TypeF类型的椭圆曲线参数: alpha0 */
    public static final BigInteger alpha0 = BigInteger.ZERO;

    /** TypeF类型的椭圆曲线参数: alpha1 */
    public static final BigInteger alpha1 = new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457C", 16);

    /** N阶循环群(G1,+)的生成元 */
    public static byte[] P1_bytes = Hex.decode(
            "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD"
                    + "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616");

    /** N阶循环群(G2,+)的生成元 */
    public static byte[] P2_bytes = Hex.decode(
            "3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B"
                    + "85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141"
                    + "A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7"
                    + "17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96");

    /**
     * 创建SM9曲线的 PairingParameters 参数对象。
     *
     * @return PairingParameters对象。
     */
    public static PairingParameters createPairingParameters() {
        PropertiesParameters params = new PropertiesParameters();
        params.put("type", "f");
        params.put("q", q.toString());
        params.put("r", N.toString());
        params.put("b", b.toString());
        params.put("beta", beta.toString());
        params.put("alpha0", alpha0.toString());
        params.put("alpha1", alpha1.toString());
        params.put("t", t.toString());

        return params;
    }
}
