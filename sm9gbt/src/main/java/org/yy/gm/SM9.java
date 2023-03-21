package org.yy.gm;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.yy.gm.engines.SM9EncryptEngine;
import org.yy.gm.engines.SM9KEMEngine;
import org.yy.gm.generators.SM9MasterKeyPairGenerator;
import org.yy.gm.generators.SM9PrivateKeyGenerator;
import org.yy.gm.generators.pairing.SM9Pairing;
import org.yy.gm.params.SM9CurveParameters;
import org.yy.gm.params.SM9KDMParameters;
import org.yy.gm.params.SM9KEMParameters;
import org.yy.gm.params.SM9KeyPairGenerationParameters;
import org.yy.gm.params.SM9Parameters;
import org.yy.gm.params.SM9SecretKeyGeneratorParameters;
import org.yy.gm.structs.SM9Cipher;
import org.yy.gm.structs.SM9KeyPackage;
import org.yy.gm.structs.SM9KeyPair;
import org.yy.gm.structs.SM9MasterSecretKey;
import org.yy.gm.structs.SM9PublicKey;
import org.yy.gm.structs.SM9SecretKey;

import java.security.SecureRandom;

import it.unisa.dia.gas.crypto.kem.KeyEncapsulationMechanism;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * SM9算法使用类。
 *
 * @author yaoyuan
 * @since 2023/3/12 15:53
 */
public class SM9 {
    public static int MAC_KEY_LEN = 32;

    public static byte HID_ENCRYPT = 0x03;

    private final SM9Parameters parameters;

    public SM9() {
        this.parameters = createParameters(new SecureRandom());
    }

    public SM9(SM9Parameters parameters) {
        this.parameters = parameters;
    }

    public SM9Parameters getParameters() {
        return parameters;
    }

    public static SM9Parameters createParameters(SecureRandom random) {
        PairingParameters parameters = SM9CurveParameters.createPairingParameters();
        SM9Pairing pairing = new SM9Pairing(random, parameters);
        Element P1 = pairing.getG1().newElementFromBytes(SM9CurveParameters.P1_bytes).getImmutable();
        Element P2 = pairing.getG2().newElementFromBytes(SM9CurveParameters.P2_bytes).getImmutable();
        return new SM9Parameters(random, pairing, P1, P2);
    }

    /**
     * Setup.
     * <p>
     * 初始化，同时生成主密钥对。
     *
     * @return 密钥对
     */
    public SM9KeyPair setup() {
        SM9MasterKeyPairGenerator masterKeyPairGenerator = new SM9MasterKeyPairGenerator();
        masterKeyPairGenerator.init(new SM9KeyPairGenerationParameters(parameters));
        return (SM9KeyPair) masterKeyPairGenerator.generateKeyPair();
    }

    /**
     * 生成秘密密钥。
     *
     * @param masterSecretKey 主秘密密钥
     * @param id 用户标识
     * @return 秘密密钥
     */
    public SM9SecretKey keyGen(SM9MasterSecretKey masterSecretKey, String id) {
        SM9PrivateKeyGenerator privateKeyGenerator = new SM9PrivateKeyGenerator();
        privateKeyGenerator.init(new SM9SecretKeyGeneratorParameters(masterSecretKey, id, HID_ENCRYPT));
        return (SM9SecretKey) privateKeyGenerator.generateKey();
    }


    /**
     * 密钥封装。
     *
     * @param publicKey  加密主公钥
     * @param peerId     对方标识。即解封人的用户标识，用对方的标识封装一个密钥后，只有对方用他自己的私钥才能解开
     * @param keyByteLen 要封装的密钥长度
     * @return 密钥封装结果
     */
    public SM9KeyPackage keyEncaps(SM9PublicKey publicKey, String peerId, int keyByteLen) {
        KeyEncapsulationMechanism kem = new SM9KEMEngine();
        kem.init(true, new SM9KEMParameters(publicKey, peerId, HID_ENCRYPT, keyByteLen));
        try {
            return SM9KeyPackage.fromByteArray(publicKey, kem.process());
        } catch (InvalidCipherTextException e) {
            // 密钥解封的 process 抛出的异常，所以不会走到这里。
            throw new RuntimeException(e);
        }
    }

    /**
     * 密钥解封。
     *
     * @param secretKey          加密私钥
     * @param myId               己方标识
     * @param keyByteLen         要解封的密钥长度
     * @param exchangeCipherText 交换密文
     * @return 密钥
     * @throws InvalidCipherTextException 交换密文不在G1上时抛出此异常
     */
    public byte[] keyDecaps(SM9SecretKey secretKey, String myId, int keyByteLen, byte[] exchangeCipherText) throws InvalidCipherTextException {
        KeyEncapsulationMechanism kem = new SM9KEMEngine();
        kem.init(false, new SM9KDMParameters(secretKey, myId, keyByteLen));
//        kem.processBlock(keyCipherText); //该方法内部传参时把 inOff 和 inLen 弄反了，导致错误，所以不使用
        return kem.processBlock(exchangeCipherText, 0, exchangeCipherText.length);
    }

    /**
     * 加密。
     *
     * @param publicKey 加密主公钥
     * @param peerId    对方标识
     * @param data      数据
     * @return 密文
     * @throws InvalidCipherTextException 如果使用对称加密且出错时就抛出此异常
     */
    public SM9Cipher encrypt(SM9PublicKey publicKey, String peerId, byte[] data) throws InvalidCipherTextException {
        KeyEncapsulationMechanism kem = new SM9EncryptEngine();
        kem.init(true, new SM9KEMParameters(
                publicKey, peerId, HID_ENCRYPT, MAC_KEY_LEN));
        return SM9Cipher.fromByteArray(publicKey, kem.processBlock(data, 0, data.length));
    }

    /**
     * 解密。
     *
     * @param secretKey  解密私钥
     * @param myId       己方标识
     * @param cipherText 密文
     * @return 明文
     * @throws InvalidCipherTextException 解密出错时就抛出此异常
     */
    public byte[] decrypt(SM9SecretKey secretKey, String myId, SM9Cipher cipherText) throws InvalidCipherTextException {
        KeyEncapsulationMechanism kem = new SM9EncryptEngine();
        kem.init(false, new SM9KDMParameters(secretKey, myId, MAC_KEY_LEN));
        byte[] temp = cipherText.toByteArray();
        return kem.processBlock(temp, 0, temp.length);
    }

}
