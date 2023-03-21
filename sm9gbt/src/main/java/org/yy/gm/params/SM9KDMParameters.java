package org.yy.gm.params;

import org.yy.gm.structs.SM9SecretKey;

/**
 * SM9密钥解封参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 1:11
 */
public class SM9KDMParameters extends SM9KEMEngineParameters {
    public SM9SecretKey secretKey;

    public SM9KDMParameters(SM9SecretKey secretKey, String myId, int keyByteLen) {
        super(secretKey, myId, keyByteLen);
        this.secretKey = secretKey;
    }
}
