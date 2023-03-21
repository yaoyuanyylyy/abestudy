package org.yy.gm.structs;


import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * SM9主密钥对。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:35
 */
public class SM9KeyPair extends AsymmetricCipherKeyPair {
    public SM9KeyPair(SM9PublicKey publicKey, SM9MasterSecretKey privateKey) {
        super(publicKey, privateKey);
    }

    @Override
    public SM9PublicKey getPublic() {
        return (SM9PublicKey) super.getPublic();
    }

    @Override
    public SM9MasterSecretKey getPrivate() {
        return (SM9MasterSecretKey) super.getPrivate();
    }
}
