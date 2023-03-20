package org.yy.gm.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9MasterKeyPairGenerationParameters;
import org.yy.gm.structs.SM9EncryptMasterKeyPair;
import org.yy.gm.structs.SM9EncryptMasterPrivateKey;
import org.yy.gm.structs.SM9EncryptMasterPublicKey;
import org.yy.gm.structs.SM9SignMasterKeyPair;
import org.yy.gm.structs.SM9SignMasterPrivateKey;
import org.yy.gm.structs.SM9SignMasterPublicKey;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9主密钥对生成器。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:27
 */
public class SM9MasterKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SM9MasterKeyPairGenerationParameters params;

    @Override
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (SM9MasterKeyPairGenerationParameters) keyGenerationParameters;
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger k = params.parameters.pairing.getZr().newRandomElement().getImmutable().toBigInteger();
        Element Q;
        if(params.isSignKey)
            Q = params.parameters.P2.mul(k).getImmutable();
        else
            Q = params.parameters.P1.mul(k).getImmutable();
        Element g = SM9Utils.preE(params.parameters, Q, params.isSignKey);

        if(params.isSignKey)
            return new SM9SignMasterKeyPair(new SM9SignMasterPublicKey(params.parameters, g, Q),
                    new SM9SignMasterPrivateKey(params.parameters, g, k));
        else
            return new SM9EncryptMasterKeyPair(new SM9EncryptMasterPublicKey(params.parameters, g, Q),
                    new SM9EncryptMasterPrivateKey(params.parameters, g, k));
    }
}
