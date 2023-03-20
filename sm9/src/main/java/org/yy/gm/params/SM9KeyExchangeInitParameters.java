package org.yy.gm.params;

import org.yy.gm.structs.SM9EncryptMasterPublicKey;

/**
 * SM9密钥协商初始化参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 23:01
 */
public class SM9KeyExchangeInitParameters extends SM9KeyParameters {
    public SM9EncryptMasterPublicKey encryptMasterPublicKey;
    public String peerId;
    public byte hid;

    public SM9KeyExchangeInitParameters(SM9EncryptMasterPublicKey encryptMasterPublicKey, String peerId, byte hid) {
        super(encryptMasterPublicKey);
        this.encryptMasterPublicKey = encryptMasterPublicKey;
        this.peerId = peerId;
        this.hid = hid;
    }
}
