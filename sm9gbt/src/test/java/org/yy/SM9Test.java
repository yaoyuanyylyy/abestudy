package org.yy;

import org.bouncycastle.crypto.CryptoException;
import org.junit.Test;
import org.yy.gm.SM9;
import org.yy.gm.SM9Utils;
import org.yy.gm.structs.SM9Cipher;
import org.yy.gm.structs.SM9KeyPackage;
import org.yy.gm.structs.SM9KeyPair;
import org.yy.gm.structs.SM9SecretKey;

/**
 * SM9测试。
 * <p>
 * test_sm9() 为一般性功能测试。
 * <p>
 * test_standard() 中的测试数据对应了 《GBT 38635.2-2020 信息安全技术 SM9标识密码算法 第2部分：算法》中的测试。
 * <p>
 * test_parameters() 测试了创建SM9参数的3种方式。
 *
 * @author yaoyuan
 * @since 2023/3/10 0:05
 */
public class SM9Test {
    @Test
    public void sm9() throws Exception {
        test_sm9();
    }

    public static void test_sm9() throws CryptoException {
        SM9 sm9 = new SM9();

        SM9LogUtils.showSM9Curve(sm9.getParameters());

        test_key_encapsulate(sm9);
        test_encrypt(sm9);
    }

    public static void test_key_encapsulate(SM9 sm9) throws CryptoException {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9密钥封装测试\n");

        String id_B = "Bob";

        SM9KeyPair keyPair = sm9.setup();
        SM9LogUtils.showMasterSecretKey(keyPair.getPrivate());
        SM9LogUtils.showPublicKey(keyPair.getPublic());

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(id_B);

        SM9SecretKey secretKey = sm9.keyGen(keyPair.getPrivate(), id_B);
        SM9LogUtils.showSecretKey(secretKey);

        int keyByteLen = 32;
        SM9LogUtils.showMsg("密钥封装的长度: " + keyByteLen + " bytes");

        SM9KeyPackage keyPackage = sm9.keyEncaps(keyPair.getPublic(), id_B, keyByteLen);
        SM9LogUtils.showMsg("密钥封装结果:");
        SM9LogUtils.showKeyPackage(keyPackage);

        byte[] key = sm9.keyDecaps(secretKey, id_B, keyByteLen, keyPackage.getC());
        SM9LogUtils.showMsg("解封后的密钥:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(key));
        SM9LogUtils.showMsg();

        if (SM9Utils.byteEqual(keyPackage.K, key))
            SM9LogUtils.showMsg("测试成功");
        else
            SM9LogUtils.showMsg("测试失败，解封后的密钥和封装的密钥不一致");
    }

    public static void test_encrypt(SM9 sm9) throws CryptoException {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9加解密测试\n");

        String id_B = "Bob";
        String msg = "Chinese IBE standard";

        SM9KeyPair keyPair = sm9.setup();
        SM9LogUtils.showMasterSecretKey(keyPair.getPrivate());
        SM9LogUtils.showPublicKey(keyPair.getPublic());

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(id_B);

        SM9SecretKey secretKey = sm9.keyGen(keyPair.getPrivate(), id_B);
        SM9LogUtils.showSecretKey(secretKey);

        SM9LogUtils.showMsg("待加密消息 M:");
        SM9LogUtils.showMsg(msg);
        SM9LogUtils.showMsg("消息M的长度: " + msg.length());

        SM9LogUtils.showMsg("加密明文的方法为基于KDF的序列密码:");
        SM9LogUtils.showMsg("");
        SM9Cipher cipherText = sm9.encrypt(keyPair.getPublic(), id_B, msg.getBytes());
        SM9LogUtils.showMsg("加密后的密文 C=C1||C3||C2:");
        SM9LogUtils.showCipherText(cipherText);

        byte[] plainText = sm9.decrypt(secretKey, id_B, cipherText);
        SM9LogUtils.showMsg("解密后的明文M':");
        SM9LogUtils.showMsg(new String(plainText));

        if (SM9Utils.byteEqual(msg.getBytes(), plainText))
            SM9LogUtils.showMsg("加解密成功");
        else
            SM9LogUtils.showMsg("加解密失败。解密后的数据与原始数据不一致。");

        SM9LogUtils.showMsg("");
    }

}