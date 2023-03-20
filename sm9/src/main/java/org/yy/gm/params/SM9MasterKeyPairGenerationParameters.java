package org.yy.gm.params;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * SM9主密钥对生成参数。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:20
 */
public class SM9MasterKeyPairGenerationParameters extends KeyGenerationParameters {
    public SM9Parameters parameters;
    public boolean isSignKey;

    public SM9MasterKeyPairGenerationParameters(SM9Parameters parameters, boolean isSignKey) {
        super(parameters.random, 0);
        this.parameters = parameters;
        this.isSignKey = isSignKey;
    }
}
