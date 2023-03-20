package org.yy.gm.engines;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.yy.gm.SM9Utils;
import org.yy.gm.cipher.CipherUtils;
import org.yy.gm.cipher.SymmMode;
import org.yy.gm.params.SM9DecryptionParameters;
import org.yy.gm.params.SM9EncryptionParameters;
import org.yy.gm.params.SM9KEMEngineParameters;
import org.yy.gm.structs.EnType;
import org.yy.gm.structs.SM9Cipher;
import org.yy.gm.structs.SM9Config;
import org.yy.gm.structs.SM9KeyPackage;

import java.io.ByteArrayOutputStream;

import it.unisa.dia.gas.plaf.jpbc.util.Arrays;

/**
 * SM9加密和解密。
 *
 * @author yaoyuan
 * @since 2023/3/10 1:29
 */
public class SM9EncryptEngine extends SM9KEMEngine {
    @Override
    public void initialize() {
        if (forEncryption) {
            if (!(key instanceof SM9EncryptionParameters))
                throw new IllegalArgumentException("SM9EncryptionParameters are required for encrypt.");
        } else if (!(key instanceof SM9DecryptionParameters))
            throw new IllegalArgumentException("SM9DecryptionParameters are required for decrypt.");

        SM9KEMEngineParameters engineParameters = (SM9KEMEngineParameters) key;
        pairing = engineParameters.parameters.pairing;
        keyBytes = engineParameters.keyByteLen;
    }

    @Override
    public byte[] process(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        return forEncryption ? encrypt(in, inOff, inLen).toByteArray() : decrypt(in, inOff, inLen);
    }



    private SM9Cipher encrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        int k1Len = CipherUtils.getSymmKeyLength(SM9Config.algSymm);
        byte[] data = Arrays.copyOfRange(in, inOff, inOff + inLen);

        SM9EncryptionParameters encryptionParameters = (SM9EncryptionParameters) key;

        boolean isBasedBlockCipher = !encryptionParameters.enType.equals(EnType.XOR);
        boolean isECB = encryptionParameters.enType.equals(EnType.ECB);

        if(!isBasedBlockCipher)
            k1Len = data.length;

        SM9KeyPackage keyPackage;
        byte[] K1;
        byte[] K2;
        boolean isK1AllZero;
        do {
            keyBytes += k1Len;
            keyPackage = keyEncapsulate();
            keyBytes -= k1Len;

            K1 = Arrays.copyOfRange(keyPackage.K, 0, k1Len);
            K2 = Arrays.copyOfRange(keyPackage.K, k1Len, keyPackage.K.length);
            isK1AllZero = SM9Utils.isAllZero(K1);
        } while (isK1AllZero);


        byte[] iv = null;
        byte[] C2;
        //Step6_2
        if (isBasedBlockCipher) {
            //C2=Enc(K1,M)
            try {
                if(!isECB) {
                    iv = new byte[CipherUtils.getSymmIVLength(SM9Config.algSymm)];
                    if (encryptionParameters.isRandomIV)
                        encryptionParameters.parameters.random.nextBytes(iv);
                }
                C2 = CipherUtils.crypt(SM9Config.algSymm, true,
                        SymmMode.valueOf(encryptionParameters.enType.name()), K1, iv, data, 0, data.length);
            } catch (Exception e) {
                throw new InvalidCipherTextException(SM9Config.algSymm.toString() + " encrypt error.", e);
            }
        } else {
            //C2=M^K1
            C2 = SM9Utils.xor(data, K1);
        }

        //Step7 : C3=MAC(K2,C2)
        byte[] C3 = SM9Utils.MAC(K2, C2);

        if (isBasedBlockCipher && iv!=null) {
            //Insert iv in the head of C2
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(iv, 0, iv.length);
            bos.write(C2, 0, C2.length);
            C2 = bos.toByteArray();
        }

        //Step8 : C=C1|C3|C2
        return new SM9Cipher(encryptionParameters.enType, keyPackage.C, C2, C3);
    }

    private byte[] decrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        SM9DecryptionParameters decryptionParameters = (SM9DecryptionParameters) key;
        SM9Cipher cipherText = SM9Cipher
                .fromByteArray(decryptionParameters.encryptPrivateKey, in, inOff, inLen);

        boolean isBasedBlockCipher = !cipherText.enType.equals(EnType.XOR);
        boolean isECB = cipherText.enType.equals(EnType.ECB);

        byte[] C2 = cipherText.C2;

        int k1Len = CipherUtils.getSymmKeyLength(SM9Config.algSymm);
        if (!isBasedBlockCipher)
            k1Len = C2.length;

        this.keyBytes += k1Len;
        byte[] temp = new SM9KeyPackage(C2, cipherText.C1).toByteArray();
        byte[] K = keyDecapsulate(temp, 0, temp.length);
        keyBytes -= k1Len;

        byte[] K1 = Arrays.copyOfRange(K, 0, k1Len);
        byte[] K2 = Arrays.copyOfRange(K, k1Len, K.length);

        if (SM9Utils.isAllZero(K1))
            throw new InvalidCipherTextException("K1 is all zero");

        // Step3_2
        byte[] ctext = C2;
        byte[] M;
        if (isBasedBlockCipher) {
            // M=Dec(K1,C2)
            try {
                byte[] iv = null;
                if(!isECB) {
                    int ivLen = CipherUtils.getSymmIVLength(SM9Config.algSymm);
                    iv = Arrays.copyOfRange(C2, 0, ivLen);
                    ctext = Arrays.copyOfRange(C2, ivLen, C2.length);
                }
                M = CipherUtils.crypt(SM9Config.algSymm, false,
                        SymmMode.valueOf(cipherText.enType.name()), K1, iv, ctext, 0, ctext.length);
            } catch (Exception e) {
                throw new InvalidCipherTextException(SM9Config.algSymm.toString() + " decrypt error.", e);
            }
        } else {
            // M=C2^K1
            M = SM9Utils.xor(C2, K1);
        }

        // Step4 : u=MAC(K2,C2)
        byte[] u = SM9Utils.MAC(K2, ctext);
        if (!SM9Utils.byteEqual(u, cipherText.C3))
            throw new InvalidCipherTextException("C3 verify failed");

        // Step5
        return M;
    }
}
