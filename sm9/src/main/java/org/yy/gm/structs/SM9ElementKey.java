package org.yy.gm.structs;

import org.yy.gm.params.SM9KeyParameters;
import org.yy.gm.params.SM9Parameters;

import it.unisa.dia.gas.jpbc.Element;

/**
 * SM9中以 点(Element类型) 为密钥值的密钥。
 * <p>
 * 包括主公钥和用户私钥。
 * <p>
 * 《GMT 0080 6.1-e/f》中描述了签名私钥类型为加密主公钥，加密私钥类型为签名主公钥，也就是说主公钥和用户私钥都是群上的点。
 *
 * @author yaoyuan
 * @since 2023/3/12 14:57
 */
public class SM9ElementKey extends SM9KeyParameters {
    public Element Q;

    /**
     * 构造器
     *
     * @param isPrivateKey 是否为私钥
     * @param parameters   曲线参数
     * @param g            公共参数
     * @param isSignKey    是否是签名密钥
     * @param Q            密钥
     */
    public SM9ElementKey(boolean isPrivateKey, SM9Parameters parameters, Element g, boolean isSignKey, Element Q) {
        super(isPrivateKey, parameters, g, isSignKey);
        this.Q = Q;
    }
}
