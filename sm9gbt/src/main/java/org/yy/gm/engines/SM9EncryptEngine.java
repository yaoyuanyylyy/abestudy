package org.yy.gm.engines;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.yy.gm.SM9Utils;
import org.yy.gm.params.SM9KDMParameters;
import org.yy.gm.params.SM9KEMEngineParameters;
import org.yy.gm.params.SM9KEMParameters;
import org.yy.gm.structs.SM9Cipher;
import org.yy.gm.structs.SM9KeyPackage;

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
            if (!(key instanceof SM9KEMParameters))
                throw new IllegalArgumentException("SM9KEMParameters are required for encrypt.");
        } else if (!(key instanceof SM9KDMParameters))
            throw new IllegalArgumentException("SM9KDMParameters are required for decrypt.");

        SM9KEMEngineParameters engineParameters = (SM9KEMEngineParameters) key;
        pairing = engineParameters.parameters.pairing;
        keyBytes = engineParameters.keyByteLen;
    }

    @Override
    public byte[] process(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        return forEncryption ? encrypt(in, inOff, inLen).toByteArray() : decrypt(in, inOff, inLen);
    }

    private SM9Cipher encrypt(byte[] in, int inOff, int inLen) {
        byte[] data = Arrays.copyOfRange(in, inOff, inOff + inLen);
        int k1Len = data.length;

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
        //Step6_2: //C2=M^K1
        C2 = SM9Utils.xor(data, K1);

        //Step7 : C3=MAC(K2,C2)
        byte[] C3 = SM9Utils.MAC(K2, C2);

        //Step8 : C=C1|C3|C2
        return new SM9Cipher((byte)0, keyPackage.C, C2, C3);
    }

    private byte[] decrypt(byte[] in, int inOff, int inLen) throws InvalidCipherTextException {
        SM9KDMParameters decryptionParameters = (SM9KDMParameters) key;
        SM9Cipher cipherText = SM9Cipher
                .fromByteArray(decryptionParameters.secretKey, in, inOff, inLen);

        byte[] C2 = cipherText.C2;
        int k1Len = C2.length;

        this.keyBytes += k1Len;
        byte[] temp = new SM9KeyPackage(C2, cipherText.C1).toByteArray();
        byte[] K = keyDecapsulate(temp, 0, temp.length);
        keyBytes -= k1Len;

        byte[] K1 = Arrays.copyOfRange(K, 0, k1Len);
        byte[] K2 = Arrays.copyOfRange(K, k1Len, K.length);

        if (SM9Utils.isAllZero(K1))
            throw new InvalidCipherTextException("K1 is all zero");

        // Step3_2: M=C2^K1
        byte[] M = SM9Utils.xor(C2, K1);

        // Step4 : u=MAC(K2,C2)
        byte[] u = SM9Utils.MAC(K2, C2);
        if (!SM9Utils.byteEqual(u, cipherText.C3))
            throw new InvalidCipherTextException("C3 verify failed");

        // Step5
        return M;
    }
}
