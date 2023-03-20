package org.yy.gm.structs;

/**
 * SM9加密主密钥对。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:03
 */
public class SM9EncryptMasterKeyPair extends SM9MasterKeyPair {
    public SM9EncryptMasterKeyPair(SM9EncryptMasterPublicKey publicKey, SM9EncryptMasterPrivateKey privateKey) {
        super(publicKey, privateKey);
    }

    @Override
    public SM9EncryptMasterPublicKey getPublic() {
        return (SM9EncryptMasterPublicKey) super.getPublic();
    }

    @Override
    public SM9EncryptMasterPrivateKey getPrivate() {
        return (SM9EncryptMasterPrivateKey) super.getPrivate();
    }
}
