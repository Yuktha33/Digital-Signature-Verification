package com.example.dsvs.service;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

/**
 * Protects private keys at rest: PBKDF2-HMAC-SHA256 derives an AES-256 key
 * from the user's password; the PKCS#8 bytes are encrypted with AES-GCM.
 * A wrong password makes GCM authentication fail.
 */
@Component
public class KeyProtectionService {

    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private final SecureRandom random = new SecureRandom();

    public record Protected(String cipherB64, String saltB64, String ivB64) {
    }

    public Protected encrypt(byte[] plain, char[] password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(salt);
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] enc = cipher.doFinal(plain);

        Base64.Encoder b64 = Base64.getEncoder();
        return new Protected(b64.encodeToString(enc), b64.encodeToString(salt), b64.encodeToString(iv));
    }

    /** Throws AEADBadTagException when the password is wrong. */
    public byte[] decrypt(String cipherB64, String saltB64, String ivB64, char[] password)
            throws GeneralSecurityException {
        Base64.Decoder b64 = Base64.getDecoder();
        byte[] salt = b64.decode(saltB64);
        byte[] iv = b64.decode(ivB64);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(b64.decode(cipherB64));
    }

    private SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        try {
            byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, "AES");
        } finally {
            spec.clearPassword();
        }
    }
}
