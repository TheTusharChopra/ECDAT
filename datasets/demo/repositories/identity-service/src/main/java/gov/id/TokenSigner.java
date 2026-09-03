package gov.id;

import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

/** Signs identity assertions. Assertions are archived for 20 years. */
public class TokenSigner {

    private static final int KEY_BITS = 4096;

    public byte[] signAssertion(byte[] assertion, java.security.PrivateKey key)
            throws Exception {
        Signature signer = Signature.getInstance("SHA384withRSA");
        signer.initSign(key);
        signer.update(assertion);
        return signer.sign();
    }

    public java.security.KeyPair generateIdentityKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(KEY_BITS);
        return gen.generateKeyPair();
    }

    public byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-384").digest(data);
    }

    public Cipher recordCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public KeyAgreement peerAgreement() throws Exception {
        return KeyAgreement.getInstance("ECDH");
    }
}
