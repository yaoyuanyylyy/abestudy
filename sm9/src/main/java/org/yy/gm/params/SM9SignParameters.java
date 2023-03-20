package org.yy.gm.params;

import org.yy.gm.structs.SM9SignPrivateKey;

/**
 * SM9签名参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 19:59
 */
public class SM9SignParameters extends SM9KeyParameters {
    public SM9SignPrivateKey signPrivateKey;

    public SM9SignParameters(SM9SignPrivateKey signPrivateKey) {
        super(signPrivateKey);
        this.signPrivateKey = signPrivateKey;
    }
}
