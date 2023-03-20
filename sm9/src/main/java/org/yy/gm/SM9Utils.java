package org.yy.gm;

import org.yy.gm.cipher.CipherUtils;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9Parameters;
import org.yy.gm.structs.SM9MasterPublicKey;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;

/**
 * AlgStudy
 *
 * @author yaoyuan
 * @since 2023/3/12 15:11
 */
public final class SM9Utils {

    /**
     * GMT-0080 7.1 预处理杂凑函数H1.
     * <p>
     * 函数原型为：H1(byte[] data, BigInteger N). 其中的data是由一个标记0x01, 参数id, hid组成。
     * <p>
     * 在生成用户私钥时，使用用户ID计算“用户公钥”时使用此函数。
     *
     * @param id  用户标识
     * @param hid 私钥生成函数识别符
     * @param N   群的阶
     * @return 杂凑值
     */
    public static BigInteger H1(String id, byte hid, BigInteger N) {
        byte[] bID = id.getBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(0x01);
        bos.write(bID, 0, bID.length);
        bos.write((byte) hid);
        return H(bos.toByteArray(), N);
    }

    /**
     * GMT-0080 7.2 预处理杂凑函数H2.
     * <p>
     * 函数原型为：H2(byte[] data, BigInteger N). 其中的data是由一个标记0x02, 参数message, w组成。
     * <p>
     * 在签名和验签时使用此函数。
     *
     * @param message 签名消息
     * @param w       群GT的点
     * @param N       群的阶
     * @return 杂凑值
     */
    public static BigInteger H2(byte[] message, Element w, BigInteger N) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(0x02);
        bos.write(message, 0, message.length);
        byte[] temp = GTFiniteElementToByte(w);
        bos.write(temp, 0, temp.length);
        return H(bos.toByteArray(), N);
    }

    /**
     * GBT-38635.2 5.3.2.1 密码杂凑函数Hv.
     * <p>
     * 最后的计算会保证杂凑值是在 [1,N-1]范围内。
     *
     * @param Z 输入数据
     * @param N 群的阶
     * @return 杂凑值
     */
    public static BigInteger H(byte[] Z, BigInteger N) {
        double log2n = Math.log(N.doubleValue()) / Math.log(2.0);
        int hlen = (int) Math.ceil((5 * log2n) / 32);
        byte[] hashValue = KDF(Z, hlen);
        BigInteger ha = new BigInteger(1, hashValue); // set sign to positive
        return ha.mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    /**
     * GMT-0080 7.3 预处理对运算e.
     * <p>
     * e(P1,签名主公钥) 或 e(加密主公钥,P2) 这两个双线性对运行的结果可以作为公开参数，提前进行计算，
     * 这样就减小了后续算法的计算压力。
     * <p>
     * 在本项目中，把这个结果作为 g，存放在最顶层的类 SM9KeyParameters 中，在生成主密钥对时调用此函数。
     *
     * @param parameters SM9参数
     * @param Q          公钥
     * @param isSignKey  是否是签名密钥
     * @return 群GT的点
     */
    public static Element preE(SM9Parameters parameters, Element Q, boolean isSignKey) {
        if (isSignKey)
            return parameters.pairing.pairing(parameters.P1, Q).getImmutable();
        else
            return parameters.pairing.pairing(Q, parameters.P2).getImmutable();
    }

    /**
     * GMT-0080 7.4&7.5 预处理用户验签或用户加密的Q.
     * <p>
     * 是使用用户ID来计算“用户公钥”的。仅在验签，密钥封装，加密，密钥协商初始化时使用。
     *
     * @param masterPublicKey 签名或加密主公钥
     * @param hid             私钥生成函数识别符
     * @param id              用户标识
     * @return 标准中的返回描述为签名主公钥或加密主公钥对象，这里直接返回 Element，以便在代码中使用。
     */
    public static Element preQ(SM9MasterPublicKey masterPublicKey, byte hid, String id) {
        // Q =[H1(ID||hid, N)]P +Ppub
        BigInteger h1 = H1(id, hid, masterPublicKey.parameters.N);
        if (masterPublicKey.isSignKey)
            return masterPublicKey.parameters.P2.mul(h1).add(masterPublicKey.Q).getImmutable();
        else
            return masterPublicKey.parameters.P1.mul(h1).add(masterPublicKey.Q).getImmutable();
    }

    /**
     * GBT-38635 5.3.6 密钥派生函数。
     * <p>
     * 在密钥封装解封、加密解密中用到.
     *
     * @param C          群G1上的点
     * @param w          群GT上的点
     * @param id         用户标识
     * @param keyByteLen 要生成的密钥长度
     * @return 密钥
     */
    public static byte[] KDF(Element C, Element w, String id, int keyByteLen) {
        // K = KDF(C || w || IDB, klen)
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] temp = C.toBytes();
        bos.write(temp, 0, temp.length);
        temp = SM9Utils.GTFiniteElementToByte(w);
        bos.write(temp, 0, temp.length);
        temp = id.getBytes();
        bos.write(temp, 0, temp.length);
        return SM9Utils.KDF(bos.toByteArray(), keyByteLen);
    }

    /**
     * 哈希函数。
     * <p>
     * 在密钥交换中计算哈希值S时用到。
     *
     * @param data 输入数据
     * @return 哈希值
     */
    public static byte[] Hash(byte[] data) {
        MessageDigest digest = CipherUtils.createDigest();
        digest.update(data, 0, data.length);
        return digest.digest();
    }

    /**
     * 密钥派生函数。
     *
     * @param data       数据
     * @param keyByteLen 密钥长度
     * @return 密钥
     */
    public static byte[] KDF(byte[] data, int keyByteLen) {
        MessageDigest digest = CipherUtils.createDigest();
        int groupNum = (keyByteLen * 8 + (digest.getDigestLength() * 8 - 1)) / (digest.getDigestLength() * 8);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int ct = 1; ct <= groupNum; ct++) {
            digest.reset();
            digest.update(data, 0, data.length);
            digest.update((byte) (ct >> 24 & 0xff));
            digest.update((byte) (ct >> 16 & 0xff));
            digest.update((byte) (ct >> 8 & 0xff));
            digest.update((byte) (ct & 0xff));
            bos.write(digest.digest(), 0, digest.getDigestLength());
        }

        return Arrays.copyOfRange(bos.toByteArray(), 0, keyByteLen);
    }

    /**
     * GBT-38635 5.3.5 消息认证码函数。
     * <p>
     * 仅在加密解密中用来计算C3.
     *
     * @param key  密钥
     * @param data 数据
     * @return mac值
     */
    public static byte[] MAC(byte[] key, byte[] data) {
        MessageDigest digest = CipherUtils.createDigest();
        digest.update(data, 0, data.length);
        digest.update(key, 0, key.length);
        return digest.digest();
    }

    /**
     * 将群G1上的点转换为字节数组。
     *
     * @param e1 群G1上的点
     * @return 字节数组
     */
    public static byte[] G1ElementToByte(Element e1) {
        return e1.toBytes();
    }


    /**
     * 将群G2上的点转换为字节数组。
     * <p>
     * 此方法转换后的数据和点的 toBytes() 转换的数据，是分组倒序的。
     *
     * @param e2 群G2上的点
     * @return 字节数组
     */
    public static byte[] G2ElementToByte(Element e2) {
        byte[] source = e2.toBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        int len = SM9CurveParameters.LEN_N;

        for (int i = 0; i < 2; i++) {
            bos.write(source, (i * 2 + 1) * len, len);
            bos.write(source, (i * 2) * len, len);
        }

        return bos.toByteArray();
    }

    /**
     * 将群GT上的点转换为字节数组。
     * <p>
     * 此方法转换后的数据和点的 toBytes() 转换的数据，是分组倒序的。
     *
     * @param et 群GT上的点
     * @return 字节数组
     */
    public static byte[] GTFiniteElementToByte(Element et) {
        byte[] source = et.toBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        int len = SM9CurveParameters.LEN_N;

        for (int i = 2; i >= 0; i--) {
            bos.write(source, ((i * 2 + 1) + 6) * len, len);
            bos.write(source, (i * 2 + 6) * len, len);

            bos.write(source, (i * 2 + 1) * len, len);
            bos.write(source, (i * 2) * len, len);
        }

        return bos.toByteArray();
    }

    /**
     * 判断一个大数是否在[1, N-1]之间。
     *
     * @param a 大数
     * @param N 群的阶
     * @return 是或否
     */
    public static boolean isInN(BigInteger a, BigInteger N) {
        return a.compareTo(BigInteger.ZERO) > 0 && a.compareTo(N) < 0;
    }

    /** Convert BitInteger to byte array, remove zero byte ahead for positive. */
    public static byte[] bigIntegerToBytes(BigInteger b) {
        byte[] temp = b.toByteArray();
        if (b.signum() > 0)
            if (temp[0] == 0)
                temp = Arrays.copyOfRange(temp, 1, temp.length);
        return temp;
    }

    /** Convert BigInteger to byte array with length at least, append zero ahead if necessary. */
    public static byte[] bigIntegerToBytes(BigInteger b, int length) {
        byte[] temp = b.toByteArray();
        if (b.signum() > 0)
            if (temp[0] == 0)
                temp = Arrays.copyOfRange(temp, 1, temp.length);

        if (temp.length < length) {
            byte[] result = new byte[length];
            System.arraycopy(temp, 0, result, length - temp.length, temp.length);
            return result;
        } else {
            return temp;
        }
    }

    public static boolean isAllZero(byte[] in) {
        for (byte b : in) {
            if (b != 0)
                return false;
        }
        return true;
    }

    public static byte[] xor(byte[] b1, byte[] b2) {
        int length = Math.min(b1.length, b2.length);
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++)
            result[i] = (byte) ((b1[i] ^ b2[i]) & 0xFF);
        return result;
    }

    public static boolean byteEqual(byte[] a, byte[] b) {
        return byteCompare(a, b) == 0;
    }

    public static int byteCompare(byte[] a, byte[] b) {
        int lena = a.length;
        int lenb = b.length;

        int len = Math.min(lena, lenb);

        for (int i = 0; i < len; i++) {
            if (a[i] < b[i])
                return -1 * (i + 1);
            else if (a[i] > b[i])
                return i + 1;
        }

        if (lena < lenb)
            return -(len + 1);
        else if (lena > lenb)
            return len + 1;
        else
            return 0;
    }
}
