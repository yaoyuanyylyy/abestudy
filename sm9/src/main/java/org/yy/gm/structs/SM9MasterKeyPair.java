package org.yy.gm.structs;


import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * SM9主密钥对。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:35
 */
public class SM9MasterKeyPair extends AsymmetricCipherKeyPair {
    public SM9MasterKeyPair(SM9MasterPublicKey publicKey, SM9MasterPrivateKey privateKey) {
        super(publicKey, privateKey);
    }

    @Override
    public SM9MasterPublicKey getPublic() {
        return (SM9MasterPublicKey) super.getPublic();
    }

    @Override
    public SM9MasterPrivateKey getPrivate() {
        return (SM9MasterPrivateKey) super.getPrivate();
    }
}
