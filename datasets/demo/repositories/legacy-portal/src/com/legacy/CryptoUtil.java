package com.legacy;

import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 * Legacy crypto helper. Written in 2009, still deployed.
 * TODO: migrate away from DESede and SHA-1.
 */
public class CryptoUtil {

    public static byte[] legacyEncrypt(byte[] data, javax.crypto.SecretKey k)
            throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(data);
    }

    public static String passwordHash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(password.getBytes()));
    }

    public static byte[] documentDigest(byte[] doc) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(doc);
    }

    public static java.security.KeyPair weakKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        return g.generateKeyPair();
    }

    public static Mac legacyMac() throws Exception {
        return Mac.getInstance("HmacSHA1");
    }
}
