package org.yy.gm.params;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * SM9主密钥对生成参数。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:20
 */
public class SM9KeyPairGenerationParameters extends KeyGenerationParameters {
    public SM9Parameters parameters;

    public SM9KeyPairGenerationParameters(SM9Parameters parameters) {
        super(parameters.random, 0);
        this.parameters = parameters;
    }
}
