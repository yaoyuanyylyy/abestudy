package org.yy.gm.cipher;

/**
 * 对称算法。
 *
 * @author yaoyuan
 * @since 2023/3/18 14:02
 */
public enum AlgSymm {
    AES128("AES"),
    AES192("AES"),
    AES256("AES"),
    DES("DES"),
    DESede("DESede"),
    DESede3("DESede"),
    SM4("SM4");

    private final String name;

    AlgSymm(String name) {
        this.name = name;
    }

    public String getName() { return name; }

    @Override
    public String toString() {
        return name;
    }
}
