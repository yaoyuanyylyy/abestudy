package org.yy.gm.structs;

/**
 * SM9加密解密使用的加密类型。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:05
 */
public enum EnType {
    XOR(0),
    ECB(1),
    CBC(2),
    OFB(4),
    CFB(8);

    private final int value;

    EnType(int value) {
        this.value =value;
    }

    public int value() {
        return value;
    }
}
