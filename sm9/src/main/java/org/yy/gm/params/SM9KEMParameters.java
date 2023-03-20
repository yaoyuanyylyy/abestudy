package org.yy.gm.params;

import org.yy.gm.structs.SM9EncryptMasterPublicKey;

/**
 * SM9密钥封装参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 1:10
 */
public class SM9KEMParameters extends SM9KEMEngineParameters {
    public SM9EncryptMasterPublicKey encryptMasterPublicKey;
    public byte hid;

    public SM9KEMParameters(SM9EncryptMasterPublicKey encryptMasterPublicKey, String peerId, byte hid, int keyByteLen) {
        super(encryptMasterPublicKey, peerId, keyByteLen);
        this.encryptMasterPublicKey = encryptMasterPublicKey;
        this.hid = hid;
    }
}
