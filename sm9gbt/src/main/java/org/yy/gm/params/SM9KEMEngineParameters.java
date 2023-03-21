package org.yy.gm.params;

/**
 * SM9 KEM 引擎参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 1:09
 */
public class SM9KEMEngineParameters extends SM9KeyParameters {
    public String id;
    public int keyByteLen;

    public SM9KEMEngineParameters(SM9KeyParameters keyParameters, String id, int keyByteLen) {
        super(keyParameters);
        this.id = id;
        this.keyByteLen = keyByteLen;
    }
}
