package org.yy.gm.params;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import it.unisa.dia.gas.jpbc.Element;


/**
 * SM9密钥参数。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:51
 */
public class SM9KeyParameters extends AsymmetricKeyParameter {
    public SM9Parameters parameters;
    /** 系统公共参数。在多个算法中用到的 运算e 的结果值，是在生成主密钥对时计算的，这样可以提高算法性能 */
    public Element g;

    public SM9KeyParameters(SM9KeyParameters keyParameters) {
        this(keyParameters.isPrivate(), keyParameters.parameters, keyParameters.g);
    }

    public SM9KeyParameters(boolean isPrivateKey, SM9Parameters parameters, Element g) {
        super(isPrivateKey);
        this.parameters = parameters;
        this.g = g;
    }

    public SM9KeyParameters(boolean isPrivateKey, SM9KeyParameters keyParameters) {
        this(isPrivateKey, keyParameters.parameters, keyParameters.g);
    }

}
