package org.yy.gm.params;


import org.yy.gm.structs.SM9EncryptMasterPrivateKey;
import org.yy.gm.structs.SM9EncryptMasterPublicKey;
import org.yy.gm.structs.SM9EncryptPrivateKey;

/**
 * SM9密钥协商参数。
 *
 * @author yaoyuan
 * @since 2023/3/10 23:04
 */
public class SM9KeyExchangeParameters extends SM9KeyExchangeInitParameters {
    public boolean isSponsor;
    public String myId;
    public SM9EncryptPrivateKey myPrivateKey;
    public SM9EncryptMasterPrivateKey myTempPrivateKey;
    public SM9EncryptMasterPublicKey myTempPublicKey;
    public SM9EncryptMasterPublicKey peerTempPublicKey;
    public int keyByteLen;

    public SM9KeyExchangeParameters(SM9EncryptMasterPublicKey masterPublicKey,
                                    boolean isSponsor, String myId, String peerId,
                                    SM9EncryptPrivateKey myPrivateKey,
                                    SM9EncryptMasterPrivateKey myTempPrivateKey,
                                    SM9EncryptMasterPublicKey myTempPublicKey,
                                    SM9EncryptMasterPublicKey peerTempPublicKey, int keyByteLen) {
        super(masterPublicKey, peerId, (byte)0); //hid not used, so set it to 0.
        this.isSponsor = isSponsor;
        this.myId = myId;
        this.myPrivateKey = myPrivateKey;
        this.myTempPrivateKey = myTempPrivateKey;
        this.myTempPublicKey = myTempPublicKey;
        this.peerTempPublicKey = peerTempPublicKey;
        this.keyByteLen = keyByteLen;
    }

}
