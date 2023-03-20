package org.yy.gm.structs;

import java.io.ByteArrayOutputStream;

/**
 * SM9密钥协商结果。
 * <p>
 * 密钥协商结果没有序列化需求，所以不提供和byte[]的互相转换方法。
 *
 * @author yaoyuan
 * @since 2023/3/10 23:37
 */
public class SM9KeyAgreement {
    public byte[] SK;
    public byte[] SA2;
    public byte[] SB1;

    public SM9KeyAgreement(byte[] SK, byte[] SA2, byte[] SB1) {
        this.SK = SK;
        this.SA2 = SA2;
        this.SB1 = SB1;
    }

    /**
     * 获取协商的会话密钥。
     *
     * @return 会话密钥
     */
    public byte[] getKey() {
        return SK;
    }

    /**
     * 获取哈希值。
     *
     * @return SA2+SB1
     */
    public byte[] getHash() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(SA2, 0, SA2.length);
        bos.write(SB1, 0, SB1.length);
        return bos.toByteArray();
    }
}
