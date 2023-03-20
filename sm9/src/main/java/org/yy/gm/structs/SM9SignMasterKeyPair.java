package org.yy.gm.structs;


/**
 * SM9签名主密钥对。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:35
 */
public class SM9SignMasterKeyPair extends SM9MasterKeyPair {
    public SM9SignMasterKeyPair(SM9SignMasterPublicKey publicKey, SM9SignMasterPrivateKey privateKey) {
        super(publicKey, privateKey);
    }

    @Override
    public SM9SignMasterPublicKey getPublic() {
        return (SM9SignMasterPublicKey) super.getPublic();
    }

    @Override
    public SM9SignMasterPrivateKey getPrivate() {
        return (SM9SignMasterPrivateKey) super.getPrivate();
    }
}
