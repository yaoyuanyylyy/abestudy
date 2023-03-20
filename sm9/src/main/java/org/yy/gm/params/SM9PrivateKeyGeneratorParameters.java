package org.yy.gm.params;

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.yy.gm.structs.SM9MasterPrivateKey;

/**
 * SM9私钥生成参数。
 *
 * @author yaoyuan
 * @since 2023/3/9 23:23
 */
public class SM9PrivateKeyGeneratorParameters extends KeyGenerationParameters {
    protected SM9MasterPrivateKey masterPrivateKey;
    protected String id;
    protected byte hid;

    public SM9PrivateKeyGeneratorParameters(SM9MasterPrivateKey masterPrivateKey, String id, byte hid) {
        super(masterPrivateKey.parameters.random, 0);
        this.masterPrivateKey = masterPrivateKey;
        this.hid = hid;
        this.id = id;
    }

    public SM9MasterPrivateKey getMasterPrivateKey() {
        return masterPrivateKey;
    }

    public byte getHid() {
        return hid;
    }

    public String getId() {
        return id;
    }
}
