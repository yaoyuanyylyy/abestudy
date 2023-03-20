package org.yy.gm;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Signer;
import org.yy.gm.engines.SM9EncryptEngine;
import org.yy.gm.engines.SM9KEMEngine;
import org.yy.gm.engines.SM9KeyExchange;
import org.yy.gm.engines.SM9Signer;
import org.yy.gm.generators.SM9MasterKeyPairGenerator;
import org.yy.gm.generators.SM9ParametersGenerator;
import org.yy.gm.generators.SM9PrivateKeyGenerator;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9DecryptionParameters;
import org.yy.gm.params.SM9EncryptionParameters;
import org.yy.gm.params.SM9KDMParameters;
import org.yy.gm.params.SM9KEMParameters;
import org.yy.gm.params.SM9KeyExchangeInitParameters;
import org.yy.gm.params.SM9KeyExchangeParameters;
import org.yy.gm.params.SM9MasterKeyPairGenerationParameters;
import org.yy.gm.params.SM9Parameters;
import org.yy.gm.params.SM9PrivateKeyGeneratorParameters;
import org.yy.gm.params.SM9SignParameters;
import org.yy.gm.params.SM9VerifyParameters;
import org.yy.gm.structs.EnType;
import org.yy.gm.structs.SM9Cipher;
import org.yy.gm.structs.SM9Config;
import org.yy.gm.structs.SM9EncryptMasterKeyPair;
import org.yy.gm.structs.SM9EncryptMasterPrivateKey;
import org.yy.gm.structs.SM9EncryptMasterPublicKey;
import org.yy.gm.structs.SM9EncryptPrivateKey;
import org.yy.gm.structs.SM9KeyAgreement;
import org.yy.gm.structs.SM9KeyPackage;
import org.yy.gm.structs.SM9MasterKeyPair;
import org.yy.gm.structs.SM9MasterPrivateKey;
import org.yy.gm.structs.SM9PrivateKey;
import org.yy.gm.structs.SM9SignMasterKeyPair;
import org.yy.gm.structs.SM9SignMasterPrivateKey;
import org.yy.gm.structs.SM9SignMasterPublicKey;
import org.yy.gm.structs.SM9SignPrivateKey;
import org.yy.gm.structs.SM9Signature;

import java.security.SecureRandom;

import it.unisa.dia.gas.crypto.kem.KeyEncapsulationMechanism;

/**
 * SM9算法使用类。
 * <p>
 * 1. 方法参数中屏蔽 私钥生成函数识别符-hid，在内部使用配置类 {@link SM9Config} 中的值，可以在那里配置。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:53
 */
public class SM9 {
    private final SM9Parameters parameters;

    public SM9() {
        this.parameters = SM9ParametersGenerator.createParameters(new SecureRandom(), SM9CurveParameters.createPairingParameters());
    }

    public SM9(SM9Parameters parameters) {
        this.parameters = parameters;
    }

    public SM9Parameters getParameters() {
        return parameters;
    }

    /**
     * Setup.
     * <p>
     * 返回主密钥对，需要显示地转换为 {@link SM9EncryptMasterKeyPair} 或 {@link SM9SignMasterKeyPair}。
     * <p>
     * 如果不想显示转换，可使用  {@link #genEncryptMasterKeyPair()}  或 {@link #genSignMasterKeyPair()}。
     *
     * @param isSignKey 是否是签名主密钥对
     * @return 主密钥对。
     */
    public SM9MasterKeyPair genMasterKeyPair(boolean isSignKey) {
        SM9MasterKeyPairGenerator masterKeyPairGenerator = new SM9MasterKeyPairGenerator();
        masterKeyPairGenerator.init(new SM9MasterKeyPairGenerationParameters(parameters, isSignKey));
        return (SM9MasterKeyPair) masterKeyPairGenerator.generateKeyPair();
    }

    /**
     * Setup: 生成加密主密钥对。
     *
     * @return 加密主密钥对
     */
    public SM9EncryptMasterKeyPair genEncryptMasterKeyPair() {
        return (SM9EncryptMasterKeyPair) genMasterKeyPair(false);
    }

    /**
     * Setup: 生成签名主密钥对。
     *
     * @return 签名主密钥对
     */
    public SM9SignMasterKeyPair genSignMasterKeyPair() {
        return (SM9SignMasterKeyPair) genMasterKeyPair(true);
    }

    /**
     * KeyGen: 生成私钥。
     * <p>
     * 返回主密钥对，需要显示地转换为 {@link SM9SignPrivateKey} 或 {@link SM9EncryptPrivateKey}。
     * <p>
     * 如果不想显示转换，可使用  {@link #genEncryptPrivateKey(SM9EncryptMasterPrivateKey, String)}
     * 或 {@link #genSignPrivateKey(SM9SignMasterPrivateKey, String)} ()}。
     *
     * @param masterPrivateKey 主私钥。可以是签名主私钥或加密主私钥
     * @param id               用户标识
     * @return 用户私钥
     */
    public SM9PrivateKey genPrivateKey(SM9MasterPrivateKey masterPrivateKey, String id) {
        SM9PrivateKeyGenerator privateKeyGenerator = new SM9PrivateKeyGenerator();
        byte hid = masterPrivateKey.isSignKey ? SM9Config.HID_SIGN : SM9Config.HID_ENCRYPT;
        privateKeyGenerator.init(new SM9PrivateKeyGeneratorParameters(masterPrivateKey, id, hid));
        if (masterPrivateKey.isSignKey)
            return (SM9SignPrivateKey) privateKeyGenerator.generateKey();
        else
            return (SM9EncryptPrivateKey) privateKeyGenerator.generateKey();
    }

    /**
     * 生成加密私钥。
     *
     * @param encryptMasterPrivateKey 加密主私钥
     * @param id                      用户标识
     * @return 加密私钥
     */
    public SM9EncryptPrivateKey genEncryptPrivateKey(SM9EncryptMasterPrivateKey encryptMasterPrivateKey, String id) {
        return (SM9EncryptPrivateKey) genPrivateKey(encryptMasterPrivateKey, id);
    }

    /**
     * 生成签名私钥。
     *
     * @param signMasterPrivateKey 签名主私钥
     * @param id                   用户标识
     * @return 签名私钥
     */
    public SM9SignPrivateKey genSignPrivateKey(SM9SignMasterPrivateKey signMasterPrivateKey, String id) {
        return (SM9SignPrivateKey) genPrivateKey(signMasterPrivateKey, id);
    }

    /**
     * 签名。
     *
     * @param signPrivateKey 签名私钥
     * @param data 待签数据，内部会进行哈希处理
     * @return 签名值
     */
    public SM9Signature sign(SM9SignPrivateKey signPrivateKey, byte[] data) {
        SM9Signer signer = new SM9Signer();
        signer.init(true, new SM9SignParameters(signPrivateKey));
        signer.update(data, 0, data.length);
        try {
            return SM9Signature.fromByteArray(signPrivateKey, signer.generateSignature());
        } catch (CryptoException e) {
            //没有初始化时抛出此异常，这里已经初始化，所以不会走到这里。
            throw new RuntimeException(e);
        }
    }

    /**
     * 验签。
     *
     * @param signMasterPublicKey 签名主公钥
     * @param signerId 签名者标识
     * @param data 待验数据，内部会进行哈希处理
     * @param signature 签名值
     * @return 成功或失败
     */
    public boolean verify(SM9SignMasterPublicKey signMasterPublicKey, String signerId, byte[] data, SM9Signature signature) {
        Signer signer = new SM9Signer();
        signer.init(false, new SM9VerifyParameters(signMasterPublicKey, signerId, SM9Config.HID_SIGN));
        signer.update(data, 0, data.length);
        return signer.verifySignature(signature.toByteArray());
    }

    /**
     * 密钥协商第1步：初始化。
     *
     * @param encryptMasterPublicKey 加密主公钥
     * @param peerId 对方标识
     * @return 己方的临时密钥对，是加密主密钥对类型。
     */
    public SM9EncryptMasterKeyPair keyExchangeInit(SM9EncryptMasterPublicKey encryptMasterPublicKey, String peerId) {
        SM9KeyExchange keyExchange = new SM9KeyExchange();
        return keyExchange.init(new SM9KeyExchangeInitParameters(encryptMasterPublicKey, peerId, SM9Config.HID_KEY_EXCHANGE));
    }

    /**
     * 密钥协商第2步：密钥交换。
     *
     * @param encryptMasterPublicKey 加密主公钥
     * @param isSponsor 是否是发起方
     * @param myId 己方标识
     * @param peerId 对方标识
     * @param myPrivateKey 己方加密私钥
     * @param myTempPrivateKey 己方临时私钥
     * @param myTempPublicKey 己方临时公钥
     * @param peerTempPublicKey 对方临时公钥
     * @param keyByteLen 要协商的密钥字节长度
     * @return 密钥
     * @throws CryptoException 对方临时公钥不在G1上(即对方临时公钥错误)时抛出此异常
     */
    public SM9KeyAgreement keyExchange(SM9EncryptMasterPublicKey encryptMasterPublicKey,
                                       boolean isSponsor, String myId, String peerId,
                                       SM9EncryptPrivateKey myPrivateKey,
                                       SM9EncryptMasterPrivateKey myTempPrivateKey,
                                       SM9EncryptMasterPublicKey myTempPublicKey,
                                       SM9EncryptMasterPublicKey peerTempPublicKey, int keyByteLen) throws CryptoException {
        SM9KeyExchange keyExchange = new SM9KeyExchange();
        return keyExchange.calculateKey(new SM9KeyExchangeParameters(
                encryptMasterPublicKey, isSponsor, myId, peerId, myPrivateKey,
                myTempPrivateKey, myTempPublicKey, peerTempPublicKey, keyByteLen));
    }

    /**
     * 密钥封装。
     *
     * @param encryptMasterPublicKey 加密主公钥
     * @param peerId 对方标识。即解封人的用户标识，用对方的标识封装一个密钥后，只有对方用他自己的私钥才能解开
     * @param keyByteLen 要封装的密钥长度
     * @return 密钥封装结果
     */
    public SM9KeyPackage keyEncaps(SM9EncryptMasterPublicKey encryptMasterPublicKey, String peerId, int keyByteLen) {
        KeyEncapsulationMechanism kem = new SM9KEMEngine();
        kem.init(true, new SM9KEMParameters(encryptMasterPublicKey, peerId, SM9Config.HID_ENCRYPT, keyByteLen));
        try {
            return SM9KeyPackage.fromByteArray(encryptMasterPublicKey, kem.process());
        } catch (InvalidCipherTextException e) {
            //密钥解封的 process 抛出的异常，所以不会走到这里。
            throw new RuntimeException(e);
        }
    }

    /**
     * 密钥解封。
     *
     * @param encryptPrivateKey 加密私钥
     * @param myId 己方标识
     * @param keyByteLen 要解封的密钥长度
     * @param exchangeCipherText 交换密文
     * @return 密钥
     * @throws InvalidCipherTextException 交换密文不在G1上时抛出此异常
     */
    public byte[] keyDecaps(SM9EncryptPrivateKey encryptPrivateKey,
                            String myId, int keyByteLen, byte[] exchangeCipherText) throws InvalidCipherTextException {
        KeyEncapsulationMechanism kem = new SM9KEMEngine();
        kem.init(false, new SM9KDMParameters(encryptPrivateKey, myId, keyByteLen));
//        kem.processBlock(keyCipherText); //该方法内部传参时把 inOff 和 inLen 弄反了，导致错误，所以不使用
        return kem.processBlock(exchangeCipherText, 0, exchangeCipherText.length);
    }

    /**
     * 加密。
     *
     * @param encryptMasterPublicKey 加密主公钥
     * @param peerId 对方标识
     * @param data 数据
     * @param enType 密文加密类型
     * @return 密文
     * @throws InvalidCipherTextException 如果使用对称加密且出错时就抛出此异常
     */
    public SM9Cipher encrypt(SM9EncryptMasterPublicKey encryptMasterPublicKey,
                             String peerId, EnType enType, byte[] data) throws InvalidCipherTextException {
        KeyEncapsulationMechanism kem = new SM9EncryptEngine();
        kem.init(true, new SM9EncryptionParameters(
                encryptMasterPublicKey, peerId, SM9Config.HID_ENCRYPT, SM9Config.MAC_KEY_LEN, enType, SM9Config.USE_RANDOM_IV));
        return SM9Cipher.fromByteArray(encryptMasterPublicKey, kem.processBlock(data, 0, data.length));
    }

    /**
     * 解密。
     *
     * @param encryptPrivateKey 解密私钥
     * @param myId 己方标识
     * @param cipherText 密文
     * @return 明文
     * @throws InvalidCipherTextException 解密出错时就抛出此异常
     */
    public byte[] decrypt(SM9EncryptPrivateKey encryptPrivateKey, String myId, SM9Cipher cipherText) throws InvalidCipherTextException {
        KeyEncapsulationMechanism kem = new SM9EncryptEngine();
        kem.init(false, new SM9DecryptionParameters(encryptPrivateKey, myId, SM9Config.MAC_KEY_LEN));
        byte[] temp = cipherText.toByteArray();
        return kem.processBlock(temp, 0, temp.length);
    }

}
