package org.yy.gm.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.yy.gm.params.SM9KeyPairGenerationParameters;
import org.yy.gm.structs.SM9KeyPair;
import org.yy.gm.structs.SM9MasterSecretKey;
import org.yy.gm.structs.SM9PublicKey;

import java.math.BigInteger;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9主密钥对生成器。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:27
 */
public class SM9MasterKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SM9KeyPairGenerationParameters params;

    @Override
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (SM9KeyPairGenerationParameters) keyGenerationParameters;
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger k = params.parameters.pairing.getZr().newRandomElement().getImmutable().toBigInteger();
        Element Q = params.parameters.P1.mul(k).getImmutable();
        Element g = params.parameters.pairing.pairing(Q, params.parameters.P2).getImmutable();
        return new SM9KeyPair(new SM9PublicKey(params.parameters, g, Q),
                new SM9MasterSecretKey(params.parameters, g, k));
    }
}
