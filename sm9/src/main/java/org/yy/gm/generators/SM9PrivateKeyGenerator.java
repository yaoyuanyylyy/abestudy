package org.yy.gm.generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9PrivateKeyGeneratorParameters;
import org.yy.gm.structs.SM9EncryptPrivateKey;
import org.yy.gm.structs.SM9MasterPrivateKey;
import org.yy.gm.structs.SM9SignPrivateKey;

import java.math.BigInteger;

import it.unisa.dia.gas.crypto.cipher.CipherParametersGenerator;
import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9私钥生成器。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:39
 */
public class SM9PrivateKeyGenerator implements CipherParametersGenerator {
    private SM9PrivateKeyGeneratorParameters params;

    @Override
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (SM9PrivateKeyGeneratorParameters) keyGenerationParameters;
    }

    @Override
    public CipherParameters generateKey() {
        SM9MasterPrivateKey masterPrivateKey = params.getMasterPrivateKey();

        BigInteger t2 = T2(masterPrivateKey, params.getId(), params.getHid());

        Element d;
        if(masterPrivateKey.isSignKey) {
            d = masterPrivateKey.parameters.P1.mul(t2).getImmutable();
            return new SM9SignPrivateKey(masterPrivateKey.parameters, masterPrivateKey.g, d);
        } else {
            d = masterPrivateKey.parameters.P2.mul(t2).getImmutable();
            return new SM9EncryptPrivateKey(masterPrivateKey.parameters, masterPrivateKey.g, d);
        }
    }

    private static BigInteger T2(SM9MasterPrivateKey masterPrivateKey, String id, byte hid) {
        BigInteger N = masterPrivateKey.parameters.N;
        BigInteger h1 = SM9Utils.H1(id, hid, N);
        BigInteger t1 = h1.add(masterPrivateKey.getKey()).mod(N);
        if(t1.equals(BigInteger.ZERO))
            throw new RuntimeException("Need to update the master private key, because t1=0 while generate secret key for "+id+" with hid "+hid);
        return masterPrivateKey.getKey().multiply(t1.modInverse(N)).mod(N);
    }
}
