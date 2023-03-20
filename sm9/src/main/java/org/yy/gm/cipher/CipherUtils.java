package org.yy.gm.cipher;

import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.yy.gm.structs.SM9Config;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cipher Utils.
 * <p>
 * Created by YaoYuan on 2020/11/13.
 */
public final class CipherUtils {
    private CipherUtils() {
    }

    /**
     * 从此处统一获取一个Digest实例。
     *
     * @return Digest对象。
     */
    public static MessageDigest createDigest() {
        try {
            return new BCJcaJceHelper().createMessageDigest(SM9Config.algDigest.toString());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * 用密钥数组创建一个密钥对象。
     *
     * @param key 密钥
     * @return 密钥对象
     */
    public static SecretKey createKey(byte[] key) {
        return new SecretKeySpec(key, SM9Config.algSymm.toString());
    }

    /**
     * 对称加解密。
     *
     * @param algSymm 算法
     * @param isEncrypt 加密还是解密
     * @param symmMode 模式
     * @param key 密钥
     * @param iv 向量
     * @param data 数据
     * @param offset 偏移位置
     * @param length 长度
     * @return 结果
     * @throws Exception 出错时抛出此异常
     */
    public static byte[] crypt(AlgSymm algSymm, boolean isEncrypt, SymmMode symmMode, byte[] key, byte[] iv, byte[] data, int offset, int length) throws Exception {
        byte[] cipherText;

        try {
            SecretKey secretKey = new SecretKeySpec(key, algSymm.toString());
            Cipher cipher = new BCJcaJceHelper().createCipher(algSymm.toString() + "/" + symmMode.name() + "/" + SM9Config.PADDING);
            if(symmMode==SymmMode.ECB)
                cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
            else {
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(isEncrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, ivSpec);
            }

            cipherText = cipher.doFinal(data, offset, length);
        } catch (BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            throw new Exception(SM9Config.algSymm.name() + " "+(isEncrypt?"encrypt":"decrypt")+" failed with mode "+symmMode, e);
        }

        return cipherText;
    }

    /**
     * Get Digest algorithm length.
     *
     * @param algDigest digest algorithm
     * @return hash value length in bytes.
     */
    public static int getDigestLength(AlgDigest algDigest) {
        switch (algDigest) {
            case SM3:
            case SHA256:
            case SHA3_256:
                return 32;
            case MD5:
                return 16;
            case SHA1:
                return 20;
            case SHA224:
            case SHA3_224:
                return 28;
            case SHA384:
            case SHA3_384:
                return 48;
            case SHA512:
            case SHA3_512:
                return 64;
            default: //should not goto here
                throw new IllegalArgumentException("Not support this digest algorithm");
        }
    }

    /**
     * Get symmetric algorithm key length.
     *
     * @param algSymm symmetric algorithm
     * @return key length in bytes.
     */
    public static int getSymmKeyLength(AlgSymm algSymm) {
        switch (algSymm) {
            case DES:
                return 8;
            case DESede:
            case SM4:
            case AES128:
                return 16;
            case DESede3:
            case AES192:
                return 24;
            case AES256:
                return 32;
            default: //should not goto here
                throw new IllegalArgumentException("Not support this symmetric algorithm");
        }
    }

    /**
     * Get symmetric algorithm block length.
     *
     * @param algSymm symmetric algorithm
     * @return block length of group in bytes.
     */
    public static int getSymmBlockLength(AlgSymm algSymm) {
        switch (algSymm) {
            case DES:
            case DESede:
            case DESede3:
                return 8;
            case AES128:
            case AES192:
            case AES256:
            case SM4:
                return 16;
            default: //should not goto here
                throw new IllegalArgumentException("Not support this symmetric algorithm");
        }
    }

    /**
     * Get symmetric algorithm IV length with the specific mode.
     *
     * @param algSymm  symmetric algorithm
     * @return IV length in bytes.
     */
    public static int getSymmIVLength(AlgSymm algSymm) {
        return getSymmBlockLength(algSymm);
    }
}
