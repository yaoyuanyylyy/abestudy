package org.yy.gm.params;

import org.yy.gm.structs.SM9PublicKey;

/**
 * SM9密钥封装参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 1:10
 */
public class SM9KEMParameters extends SM9KEMEngineParameters {
    public SM9PublicKey publicKey;
    public byte hid;

    public SM9KEMParameters(SM9PublicKey publicKey, String peerId, byte hid, int keyByteLen) {
        super(publicKey, peerId, keyByteLen);
        this.publicKey = publicKey;
        this.hid = hid;
    }
}
