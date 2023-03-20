package org.yy.gm.params;

import org.yy.gm.structs.SM9EncryptPrivateKey;

/**
 * SM9密钥解封参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 1:11
 */
public class SM9KDMParameters extends SM9KEMEngineParameters {
    public SM9EncryptPrivateKey encryptPrivateKey;

    public SM9KDMParameters(SM9EncryptPrivateKey encryptPrivateKey, String myId, int keyByteLen) {
        super(encryptPrivateKey, myId, keyByteLen);
        this.encryptPrivateKey = encryptPrivateKey;
    }
}
