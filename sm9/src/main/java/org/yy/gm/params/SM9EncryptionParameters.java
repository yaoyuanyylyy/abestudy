package org.yy.gm.params;

import org.yy.gm.structs.EnType;
import org.yy.gm.structs.SM9EncryptMasterPublicKey;

/**
 * SM9加密参数。
 * <p>
 * 根据《GBT 38635.2-2020 信息安全技术 SM9标识密码算法 第2部分：算法》增加了两个参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 2:25
 */
public class SM9EncryptionParameters extends SM9KEMParameters {
    /** 加密模式。 */
    public EnType enType;

    /** 仅当 enType 为CBC，OFB，CFB时有效。true-表示生成随机向量；false-表示使用0向量 */
    public boolean isRandomIV;

    public SM9EncryptionParameters(SM9EncryptMasterPublicKey encryptMasterPublicKey,
                                   String peerId, byte hid, int macKeyByteLen, EnType enType, boolean isRandomIV) {
        super(encryptMasterPublicKey, peerId, hid, macKeyByteLen);
        this.enType = enType;
        this.isRandomIV = isRandomIV;
    }
}
