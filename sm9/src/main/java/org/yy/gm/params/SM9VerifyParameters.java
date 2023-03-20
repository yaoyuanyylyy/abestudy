package org.yy.gm.params;

import org.yy.gm.structs.SM9SignMasterPublicKey;

/**
 * SM9验签参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 20:05
 */
public class SM9VerifyParameters extends SM9KeyParameters {
    public SM9SignMasterPublicKey signMasterPublicKey;
    public String signerId;
    public byte hid;

    public SM9VerifyParameters(SM9SignMasterPublicKey signMasterPublicKey, String signerId, byte hid) {
        super(signMasterPublicKey);
        this.signMasterPublicKey = signMasterPublicKey;
        this.signerId = signerId;
        this.hid = hid;
    }
}
