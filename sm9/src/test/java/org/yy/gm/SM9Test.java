package org.yy.gm;

import org.bouncycastle.crypto.CryptoException;
import org.junit.Test;
import org.yy.gm.cipher.CipherUtils;
import org.yy.gm.generators.SM9CurveGenerator;
import org.yy.gm.generators.SM9ParametersGenerator;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9Parameters;
import org.yy.gm.structs.EnType;
import org.yy.gm.structs.SM9Cipher;
import org.yy.gm.structs.SM9Config;
import org.yy.gm.structs.SM9EncryptMasterKeyPair;
import org.yy.gm.structs.SM9EncryptPrivateKey;
import org.yy.gm.structs.SM9KeyAgreement;
import org.yy.gm.structs.SM9KeyPackage;
import org.yy.gm.structs.SM9SignMasterKeyPair;
import org.yy.gm.structs.SM9SignPrivateKey;
import org.yy.gm.structs.SM9Signature;
import org.yy.gm.test.SM9WithStandardTest;
import org.yy.gm.test.engines.SM9EncryptEngineTest;
import org.yy.gm.test.engines.SM9KEMEngineTest;
import org.yy.gm.test.engines.SM9KeyExchangeTest;
import org.yy.gm.test.engines.SM9SignerTest;
import org.yy.gm.test.generators.SM9MasterKeyPairGeneratorTest;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.PairingParameters;

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
        // test_sm9();
        test_standard();
    }

    public static void test_sm9() throws CryptoException {
        SM9 sm9 = new SM9();

        SM9LogUtils.showSM9Curve(sm9.getParameters());

        test_sign(sm9);
        test_key_exchange(sm9);
        test_key_encapsulate(sm9);
        test_encrypt(sm9);
    }

    public static void test_standard() throws CryptoException {
        SM9LogUtils.showHexWrap = true;
        SM9LogUtils.showHexUppercase = true;

        SM9WithStandardTest sm9 = new SM9WithStandardTest();

        SM9LogUtils.showSM9Curve(sm9.getParameters());

        test_standard_sm9_sign(sm9);
        test_standard_key_exchange(sm9);
        test_standard_key_encapsulate(sm9);
        test_standard_encrypt(sm9);

        SM9LogUtils.showHexWrap = false;
        SM9LogUtils.showHexUppercase = false;
    }

    @Test
    public void test_parameters() {

        test_params_generate();

        // test_params_saveToFile();
    }

    public static void test_params_generate() {
        // 实时生成曲线参数
        SM9Parameters parameters = SM9ParametersGenerator.createParameters(new SecureRandom());
        SM9LogUtils.showSM9Curve(parameters);
        SM9LogUtils.showMsg(parameters.pairing.getPairingParameters().toString());

        // 从参数文件载入
        parameters = SM9ParametersGenerator.createParameters(new SecureRandom(),
                SM9.class.getClassLoader().getResource("").getPath() + "/sm9.properties");
        SM9LogUtils.showSM9Curve(parameters);
        SM9LogUtils.showMsg(parameters.pairing.getPairingParameters().toString());

        // 从参数类 SM9CurveParameters 中创建
        parameters = SM9ParametersGenerator.createParameters(new SecureRandom(),
                SM9CurveParameters.createPairingParameters());
        SM9LogUtils.showSM9Curve(parameters);
        SM9LogUtils.showMsg(parameters.pairing.getPairingParameters().toString());
    }

    public static void test_params_saveToFile() {
        // 把曲线参数存入文件中
        SM9CurveGenerator pg = new SM9CurveGenerator();
        PairingParameters sm9Params = pg.generate();
        try (FileOutputStream fos = new FileOutputStream("sm9.properties")) {
            fos.write(sm9Params.toString().getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    public static void test_sign(SM9 sm9) {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9签名测试\n");

        String id_A = "Alice";

        // 生成签名主密钥对
        SM9SignMasterKeyPair keyPair = sm9.genSignMasterKeyPair();
        SM9LogUtils.showMsg("签名主私钥 ks:");
        SM9LogUtils.showMasterPrivateKey(keyPair.getPrivate());
        SM9LogUtils.showMsg("签名主公钥 Ppub-s:");
        SM9LogUtils.showMasterPublicKey(keyPair.getPublic());

        // 显示ID信息
        SM9LogUtils.showMsg("实体A的标识IDA:");
        SM9LogUtils.showMsg(id_A);
        SM9LogUtils.showMsg("IDA的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(id_A.getBytes()));

        // 生成签名私钥
        SM9LogUtils.showMsg("签名私钥 ds_A:");
        SM9SignPrivateKey privateKey = sm9.genSignPrivateKey(keyPair.getPrivate(), id_A);
        SM9LogUtils.showPrivateKey(privateKey);


        byte[] data = "Chinese IBS standard".getBytes();

        // 签名
        SM9LogUtils.showMsg("签名步骤中的相关值:");
        String msg = "Chinese IBS standard";
        SM9LogUtils.showMsg("待签名消息 M:");
        SM9LogUtils.showMsg(msg);
        SM9LogUtils.showMsg("M的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(msg.getBytes()));
        SM9SignerTest.r = new BigInteger("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16);
        SM9Signature signature = sm9.sign(privateKey, data);
        SM9LogUtils.showMsg("消息M的签名为(h,s):");
        SM9LogUtils.showResultSignature(signature);

        // 验签
        if (sm9.verify(keyPair.getPublic(), id_A, data, signature))
            SM9LogUtils.showMsg("verify OK");
        else
            SM9LogUtils.showMsg("verify failed");
    }

    public static void test_key_exchange(SM9 sm9) throws CryptoException {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9密钥交换测试\n");

        String myId = "Alice";
        String peerId = "Bob";

        SM9EncryptMasterKeyPair masterKeyPair = sm9.genEncryptMasterKeyPair();
        SM9LogUtils.showMsg("加密主私钥 ke:");
        SM9LogUtils.showMasterPrivateKey(masterKeyPair.getPrivate());
        SM9LogUtils.showMsg("加密主公钥 Ppub-e:");
        SM9LogUtils.showMasterPublicKey(masterKeyPair.getPublic());

        SM9LogUtils.showMsg("实体A的标识IDA:");
        SM9LogUtils.showMsg(myId);
        SM9LogUtils.showMsg("IDA的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(myId.getBytes()));
        SM9EncryptPrivateKey myPrivateKey = sm9.genEncryptPrivateKey(masterKeyPair.getPrivate(), myId);
        SM9LogUtils.showMsg("实体A的加密私钥 de_A:");
        SM9LogUtils.showPrivateKey(myPrivateKey);

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(peerId);
        SM9LogUtils.showMsg("IDB的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(peerId.getBytes()));
        SM9EncryptPrivateKey othPrivateKey = sm9.genEncryptPrivateKey(masterKeyPair.getPrivate(), peerId);
        SM9LogUtils.showMsg("实体B的加密私钥 de_B:");
        SM9LogUtils.showPrivateKey(othPrivateKey);

        int keyByteLen = 16;
        SM9LogUtils.showMsg("密钥交换的长度: " + keyByteLen + " bytes");

        SM9EncryptMasterKeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublic(), peerId);

        SM9EncryptMasterKeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublic(), myId);

        SM9KeyAgreement othAgreementKey = sm9.keyExchange(masterKeyPair.getPublic(), false,
                peerId, myId, othPrivateKey, othTempKeyPair.getPrivate(), othTempKeyPair.getPublic(), myTempKeyPair.getPublic(), keyByteLen);

        SM9KeyAgreement myAgreementKey = sm9.keyExchange(masterKeyPair.getPublic(), true,
                myId, peerId, myPrivateKey, myTempKeyPair.getPrivate(), myTempKeyPair.getPublic(), othTempKeyPair.getPublic(), keyByteLen);

        SM9LogUtils.showMsg("A方");
        SM9LogUtils.showMsg("SA: " + SM9LogUtils.toHexString(myAgreementKey.SA2));
        SM9LogUtils.showMsg("S1: " + SM9LogUtils.toHexString(myAgreementKey.SB1));
        SM9LogUtils.showMsg("SK: " + SM9LogUtils.toHexString(myAgreementKey.SK));

        SM9LogUtils.showMsg("B方");
        SM9LogUtils.showMsg("S2: " + SM9LogUtils.toHexString(othAgreementKey.SA2));
        SM9LogUtils.showMsg("SB: " + SM9LogUtils.toHexString(othAgreementKey.SB1));
        SM9LogUtils.showMsg("SK: " + SM9LogUtils.toHexString(othAgreementKey.SK));

        boolean isSuccess = true;
        if (SM9Utils.byteEqual(myAgreementKey.SA2, othAgreementKey.SA2))
            SM9LogUtils.showMsg("SA = S2");
        else {
            SM9LogUtils.showMsg("SA != S2");
            isSuccess = false;
        }

        if (SM9Utils.byteEqual(myAgreementKey.SB1, othAgreementKey.SB1))
            SM9LogUtils.showMsg("S1 = SB");
        else {
            SM9LogUtils.showMsg("S1 != SB");
            isSuccess = false;
        }

        if (SM9Utils.byteEqual(myAgreementKey.SK, othAgreementKey.SK))
            SM9LogUtils.showMsg("SK_A = SK_B");
        else {
            SM9LogUtils.showMsg("SK_A != SK_B");
            isSuccess = false;
        }

        if (isSuccess)
            SM9LogUtils.showMsg("密钥交换成功");
        else
            SM9LogUtils.showMsg("密钥交换失败");
    }

    public static void test_key_encapsulate(SM9 sm9) throws CryptoException {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9密钥封装测试\n");

        String id_B = "Bob";

        SM9EncryptMasterKeyPair encryptMasterKeyPair = sm9.genEncryptMasterKeyPair();

        SM9LogUtils.showMsg("加密主私钥 ke:");
        SM9LogUtils.showMasterPrivateKey(encryptMasterKeyPair.getPrivate());
        SM9LogUtils.showMsg("加密主公钥 Ppub-e:");
        SM9LogUtils.showMasterPublicKey(encryptMasterKeyPair.getPublic());

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(id_B);

        SM9EncryptPrivateKey encryptPrivateKey = sm9.genEncryptPrivateKey(encryptMasterKeyPair.getPrivate(), id_B);
        SM9LogUtils.showMsg("加密私钥 de_B:");
        SM9LogUtils.showPrivateKey(encryptPrivateKey);

        int keyByteLen = 32;
        SM9LogUtils.showMsg("密钥封装的长度: " + keyByteLen + " bytes");

        SM9KeyPackage keyPackage = sm9.keyEncaps(encryptMasterKeyPair.getPublic(), id_B, keyByteLen);
        SM9LogUtils.showMsg("密钥封装结果:");
        SM9LogUtils.showKeyPackage(keyPackage);

        byte[] key = sm9.keyDecaps(encryptPrivateKey, id_B, keyByteLen, keyPackage.getC());
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

        SM9EncryptMasterKeyPair encryptMasterKeyPair = sm9.genEncryptMasterKeyPair();

        SM9LogUtils.showMsg("加密主私钥 ke:");
        SM9LogUtils.showMasterPrivateKey(encryptMasterKeyPair.getPrivate());
        SM9LogUtils.showMsg("加密主公钥 Ppub-e:");
        SM9LogUtils.showMasterPublicKey(encryptMasterKeyPair.getPublic());

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(id_B);

        SM9EncryptPrivateKey encryptPrivateKey = sm9.genEncryptPrivateKey(encryptMasterKeyPair.getPrivate(), id_B);
        SM9LogUtils.showMsg("加密私钥 de_B:");
        SM9LogUtils.showPrivateKey(encryptPrivateKey);

        SM9LogUtils.showMsg("待加密消息 M:");
        SM9LogUtils.showMsg(msg);
        SM9LogUtils.showMsg("消息M的长度: " + msg.length() + " bytes, 0x" + (Integer.toHexString(msg.length() * 8)));

        EnType enType = EnType.XOR;
        for (int i = 0; i < 2; i++) {
            if (enType.equals(EnType.XOR))
                SM9LogUtils.showMsg("加密明文的方法为基于KDF的序列密码:");
            else
                SM9LogUtils.showMsg("加密明文的方法为分组密码算法: " + enType.name());

            SM9LogUtils.showMsg("");
            SM9Cipher cipherText = sm9.encrypt(encryptMasterKeyPair.getPublic(), id_B, enType, msg.getBytes());
            SM9LogUtils.showMsg("加密后的密文 C=C1||C3||C2:");
            SM9LogUtils.showCipherText(cipherText);

            byte[] plainText = sm9.decrypt(encryptPrivateKey, id_B, cipherText);
            SM9LogUtils.showMsg("解密后的明文M':");
            SM9LogUtils.showMsg(new String(plainText));

            if (SM9Utils.byteEqual(msg.getBytes(), plainText))
                SM9LogUtils.showMsg("加解密成功");
            else
                SM9LogUtils.showMsg("加解密失败。解密后的数据与原始数据不一致。");

            enType = EnType.CBC;
            SM9LogUtils.showMsg("");
        }
    }

    public static void test_standard_sm9_sign(SM9WithStandardTest sm9) {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9签名测试\n");

        String id_A = "Alice";

        SM9LogUtils.showMsg("签名主密钥和用户签名私钥产生过程中的相关值:");

        // 生成签名主密钥对
        SM9MasterKeyPairGeneratorTest.k = new BigInteger("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        SM9SignMasterKeyPair keyPair = sm9.genSignMasterKeyPair();
        SM9LogUtils.showMsg("签名主私钥 ks:");
        SM9LogUtils.showMasterPrivateKey(keyPair.getPrivate());
        SM9LogUtils.showMsg("签名主公钥 Ppub-s:");
        SM9LogUtils.showMasterPublicKey(keyPair.getPublic());

        // 显示ID信息
        SM9LogUtils.showMsg("实体A的标识IDA:");
        SM9LogUtils.showMsg(id_A);
        SM9LogUtils.showMsg("IDA的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(id_A.getBytes()));

        // 生成签名私钥
        SM9LogUtils.showMsg("签名私钥 ds_A:");
        SM9SignPrivateKey privateKey = sm9.genSignPrivateKey(keyPair.getPrivate(), id_A);
        SM9LogUtils.showPrivateKey(privateKey);


        byte[] data = "Chinese IBS standard".getBytes();

        // 签名
        SM9LogUtils.showMsg("签名步骤中的相关值:");
        String msg = "Chinese IBS standard";
        SM9LogUtils.showMsg("待签名消息 M:");
        SM9LogUtils.showMsg(msg);
        SM9LogUtils.showMsg("M的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(msg.getBytes()));
        SM9SignerTest.r = new BigInteger("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE", 16);
        SM9Signature signature = sm9.sign(privateKey, data);
        SM9LogUtils.showMsg("消息M的签名为(h,s):");
        SM9LogUtils.showResultSignature(signature);

        // 验签
        SM9LogUtils.showMsg("验证步骤中的相关值:");
        if (sm9.verify(keyPair.getPublic(), id_A, data, signature))
            SM9LogUtils.showMsg("verify OK");
        else
            SM9LogUtils.showMsg("verify failed");
    }

    public static void test_standard_key_exchange(SM9WithStandardTest sm9) throws CryptoException {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9密钥交换测试\n");

        String myId = "Alice";
        String peerId = "Bob";

        SM9MasterKeyPairGeneratorTest.k = new BigInteger("02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);
        SM9EncryptMasterKeyPair masterKeyPair = sm9.genEncryptMasterKeyPair();
        SM9LogUtils.showMsg("加密主私钥 ke:");
        SM9LogUtils.showMasterPrivateKey(masterKeyPair.getPrivate());
        SM9LogUtils.showMsg("加密主公钥 Ppub-e:");
        SM9LogUtils.showMasterPublicKey(masterKeyPair.getPublic());

        SM9LogUtils.showMsg("实体A的标识IDA:");
        SM9LogUtils.showMsg(myId);
        SM9LogUtils.showMsg("IDA的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(myId.getBytes()));
        SM9EncryptPrivateKey myPrivateKey = sm9.genEncryptPrivateKey(masterKeyPair.getPrivate(), myId);
        SM9LogUtils.showMsg("实体A的加密私钥 de_A:");
        SM9LogUtils.showPrivateKey(myPrivateKey);

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(peerId);
        SM9LogUtils.showMsg("IDB的16进制表示");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(peerId.getBytes()));
        SM9EncryptPrivateKey othPrivateKey = sm9.genEncryptPrivateKey(masterKeyPair.getPrivate(), peerId);
        SM9LogUtils.showMsg("实体B的加密私钥 de_B:");
        SM9LogUtils.showPrivateKey(othPrivateKey);

        int keyByteLen = 16;
        SM9LogUtils.showMsg("密钥交换的长度: " + keyByteLen + " bytes");

        SM9LogUtils.showMsg("密钥交换步骤A1-A4中的相关值:");
        SM9KeyExchangeTest.r = new BigInteger("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
        SM9EncryptMasterKeyPair myTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublic(), peerId);

        SM9LogUtils.showMsg("密钥交换步骤B1-B8中的相关值:");
        SM9KeyExchangeTest.r = new BigInteger("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
        SM9EncryptMasterKeyPair othTempKeyPair = sm9.keyExchangeInit(masterKeyPair.getPublic(), myId);

        SM9KeyAgreement othAgreementKey = sm9.keyExchange(masterKeyPair.getPublic(), false,
                peerId, myId, othPrivateKey, othTempKeyPair.getPrivate(), othTempKeyPair.getPublic(), myTempKeyPair.getPublic(), keyByteLen);

        SM9LogUtils.showMsg("密钥交换步骤A5-A8中的相关值:");
        SM9KeyAgreement myAgreementKey = sm9.keyExchange(masterKeyPair.getPublic(), true,
                myId, peerId, myPrivateKey, myTempKeyPair.getPrivate(), myTempKeyPair.getPublic(), othTempKeyPair.getPublic(), keyByteLen);

        SM9LogUtils.showMsg("A方");
        SM9LogUtils.showMsg("SA: " + SM9LogUtils.toHexString(myAgreementKey.SA2));
        SM9LogUtils.showMsg("S1: " + SM9LogUtils.toHexString(myAgreementKey.SB1));
        SM9LogUtils.showMsg("SK: " + SM9LogUtils.toHexString(myAgreementKey.SK));

        SM9LogUtils.showMsg("B方");
        SM9LogUtils.showMsg("S2: " + SM9LogUtils.toHexString(othAgreementKey.SA2));
        SM9LogUtils.showMsg("SB: " + SM9LogUtils.toHexString(othAgreementKey.SB1));
        SM9LogUtils.showMsg("SK: " + SM9LogUtils.toHexString(othAgreementKey.SK));

        boolean isSuccess = true;
        if (SM9Utils.byteEqual(myAgreementKey.SA2, othAgreementKey.SA2))
            SM9LogUtils.showMsg("SA = S2");
        else {
            SM9LogUtils.showMsg("SA != S2");
            isSuccess = false;
        }

        if (SM9Utils.byteEqual(myAgreementKey.SB1, othAgreementKey.SB1))
            SM9LogUtils.showMsg("S1 = SB");
        else {
            SM9LogUtils.showMsg("S1 != SB");
            isSuccess = false;
        }

        if (SM9Utils.byteEqual(myAgreementKey.SK, othAgreementKey.SK))
            SM9LogUtils.showMsg("SK_A = SK_B");
        else {
            SM9LogUtils.showMsg("SK_A != SK_B");
            isSuccess = false;
        }

        if (isSuccess)
            SM9LogUtils.showMsg("密钥交换成功");
        else
            SM9LogUtils.showMsg("密钥交换失败");
    }

    public static void test_standard_key_encapsulate(SM9WithStandardTest sm9) throws CryptoException {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9密钥封装测试\n");

        String id_B = "Bob";

        SM9LogUtils.showMsg("加密主密钥和用户密钥产生过程中的相关值:");

        SM9MasterKeyPairGeneratorTest.k = new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        SM9EncryptMasterKeyPair encryptMasterKeyPair = sm9.genEncryptMasterKeyPair();

        SM9LogUtils.showMsg("加密主私钥 ke:");
        SM9LogUtils.showMasterPrivateKey(encryptMasterKeyPair.getPrivate());
        SM9LogUtils.showMsg("加密主公钥 Ppub-e:");
        SM9LogUtils.showMasterPublicKey(encryptMasterKeyPair.getPublic());

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(id_B);

        SM9EncryptPrivateKey encryptPrivateKey = sm9.genEncryptPrivateKey(encryptMasterKeyPair.getPrivate(), id_B);
        SM9LogUtils.showMsg("加密私钥 de_B:");
        SM9LogUtils.showPrivateKey(encryptPrivateKey);

        int keyByteLen = 32;
        SM9LogUtils.showMsg("密钥封装的长度: " + keyByteLen + " bytes");

        SM9LogUtils.showMsg("密钥封装步骤A1-A7中的相关值:");

        SM9KEMEngineTest.r = new BigInteger("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722", 16);
        SM9KeyPackage keyPackage = sm9.keyEncaps(encryptMasterKeyPair.getPublic(), id_B, keyByteLen);
        SM9LogUtils.showMsg("密钥封装结果:");
        SM9LogUtils.showKeyPackage(keyPackage);

        SM9LogUtils.showMsg("解封装步骤B1-B4中的相关值:");
        byte[] key = sm9.keyDecaps(encryptPrivateKey, id_B, keyByteLen, keyPackage.getC());
        SM9LogUtils.showMsg("解封后的密钥:");
        SM9LogUtils.showMsg(SM9LogUtils.toHexString(key));
        SM9LogUtils.showMsg();

        if (SM9Utils.byteEqual(keyPackage.K, key))
            SM9LogUtils.showMsg("测试成功");
        else
            SM9LogUtils.showMsg("测试失败，解封后的密钥和封装的密钥不一致");
    }

    public static void test_standard_encrypt(SM9WithStandardTest sm9) throws CryptoException {
        SM9LogUtils.showMsg("\n----------------------------------------------------------------------\n");
        SM9LogUtils.showMsg("SM9加解密测试\n");

        String id_B = "Bob";
        String msg = "Chinese IBE standard";

        SM9LogUtils.showMsg("加密主密钥和用户加密密钥产生过程中的相关值:");

        SM9MasterKeyPairGeneratorTest.k = new BigInteger("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
        SM9EncryptMasterKeyPair encryptMasterKeyPair = sm9.genEncryptMasterKeyPair();

        SM9LogUtils.showMsg("加密主私钥 ke:");
        SM9LogUtils.showMasterPrivateKey(encryptMasterKeyPair.getPrivate());
        SM9LogUtils.showMsg("加密主公钥 Ppub-e:");
        SM9LogUtils.showMasterPublicKey(encryptMasterKeyPair.getPublic());

        SM9LogUtils.showMsg("实体B的标识IDB:");
        SM9LogUtils.showMsg(id_B);

        SM9EncryptPrivateKey encryptPrivateKey = sm9.genEncryptPrivateKey(encryptMasterKeyPair.getPrivate(), id_B);
        SM9LogUtils.showMsg("加密私钥 de_B:");
        SM9LogUtils.showPrivateKey(encryptPrivateKey);

        SM9LogUtils.showMsg("待加密消息 M:");
        SM9LogUtils.showMsg(msg);
        SM9LogUtils.showMsg("消息M的长度: " + msg.length() + " bytes, 0x" + (Integer.toHexString(msg.length() * 8)));
        int keyLen = CipherUtils.getSymmKeyLength(SM9Config.algSymm);
        SM9LogUtils.showMsg("K1_len: " + keyLen + " bytes, 0x" + (Integer.toHexString(keyLen * 8)));

        int macKeyByteLen = SM9Config.MAC_KEY_LEN;
        SM9LogUtils.showMsg("K2_len: " + macKeyByteLen + " bytes, 0x" + (Integer.toHexString(macKeyByteLen * 8)));

        SM9EncryptEngineTest.r = new BigInteger("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C", 16);

        EnType enType = EnType.XOR;
        for (int i = 0; i < 2; i++) {
            SM9LogUtils.showMsg("");
            SM9LogUtils.showMsg("加密算法步骤A1-A8中的相关值:");
            SM9Cipher cipherText = sm9.encrypt(encryptMasterKeyPair.getPublic(), id_B, enType, msg.getBytes());
            SM9LogUtils.showMsg("加密后的密文 C=C1||C3||C2:");
            SM9LogUtils.showCipherText(cipherText);

            SM9LogUtils.showMsg("");
            SM9LogUtils.showMsg("解密算法步骤B1-B5中的相关值:");
            byte[] plainText = sm9.decrypt(encryptPrivateKey, id_B, cipherText);
            SM9LogUtils.showMsg("解密后的明文M':");
            SM9LogUtils.showMsg(new String(plainText));

            if (SM9Utils.byteEqual(msg.getBytes(), plainText))
                SM9LogUtils.showMsg("加解密成功");
            else
                SM9LogUtils.showMsg("加解密失败。解密后的数据与原始数据不一致。");

            enType = EnType.CBC;
        }
    }
}
