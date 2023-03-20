package org.yy.gm.cipher;

/**
 * 哈希算法。
 *
 * @author yaoyuan
 * @since 2023/3/18 14:02
 */
public enum AlgDigest {
    SM3("SM3"),
    MD5("MD5"),
    SHA1("SHA1"),
    SHA224("SHA224"),
    SHA256("SHA256"),
    SHA384("SHA384"),
    SHA512("SHA512"),
    SHA3_224("SHA3-224"),
    SHA3_256("SHA3-256"),
    SHA3_384("SHA3-384"),
    SHA3_512("SHA3-512");

    private final String name;

    AlgDigest(String name) {
        this.name = name;
    }

    public String getName() { return name; }

    @Override
    public String toString() {
        return name;
    }
}
