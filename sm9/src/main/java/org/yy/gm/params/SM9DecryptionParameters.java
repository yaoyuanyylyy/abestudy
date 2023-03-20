package org.yy.gm.params;

import org.yy.gm.structs.SM9EncryptPrivateKey;

/**
 * SM9解密参数。
 * <p>
 * EnType包含在密文中。
 *
 * @author yaoyuan
 * @since 2023/3/10 2:26
 */
public class SM9DecryptionParameters extends SM9KDMParameters {
    public SM9DecryptionParameters(SM9EncryptPrivateKey encryptPrivateKey, String myId, int macKeyByteLen) {
        super(encryptPrivateKey, myId, macKeyByteLen);
    }
}
