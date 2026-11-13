package com.example.dsvs.service;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import javax.crypto.AEADBadTagException;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.example.dsvs.dto.SignResponse;
import com.example.dsvs.dto.VerifyResponse;
import com.example.dsvs.entity.KeyPairEntity;
import com.example.dsvs.entity.SignatureRecord;
import com.example.dsvs.entity.VerificationLog;
import com.example.dsvs.exception.ApiException;
import com.example.dsvs.repository.SignatureRecordRepository;
import com.example.dsvs.repository.VerificationLogRepository;

@Service
public class SignatureService {

    private final KeyService keyService;
    private final KeyProtectionService protection;
    private final SignatureRecordRepository recordRepo;
    private final VerificationLogRepository logRepo;

    public SignatureService(KeyService keyService, KeyProtectionService protection,
                            SignatureRecordRepository recordRepo, VerificationLogRepository logRepo) {
        this.keyService = keyService;
        this.protection = protection;
        this.recordRepo = recordRepo;
        this.logRepo = logRepo;
    }

    // ------------------------------------------------------------ SIGN
    public SignResponse sign(String documentName, byte[] data, String alias, String password) {
        KeyPairEntity key = keyService.get(alias);
        String sigAlg = signatureAlgorithm(key.getAlgorithm());

        byte[] pkcs8 = null;
        try {
            pkcs8 = protection.decrypt(key.getEncryptedPrivateKey(), key.getSalt(), key.getIv(),
                    password.toCharArray());
            PrivateKey privateKey = KeyFactory.getInstance(key.getAlgorithm())
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

            Signature signer = Signature.getInstance(sigAlg);
            signer.initSign(privateKey);
            signer.update(data);
            String signatureB64 = Base64.getEncoder().encodeToString(signer.sign());

            SignatureRecord rec = new SignatureRecord();
            rec.setDocumentName(documentName == null ? "unnamed" : documentName);
            rec.setDocumentHash(sha256Hex(data));
            rec.setKeyAlias(alias);
            rec.setAlgorithm(sigAlg);
            rec.setSignature(signatureB64);
            rec = recordRepo.save(rec);

            return new SignResponse(rec.getId(), rec.getDocumentName(), rec.getDocumentHash(),
                    rec.getAlgorithm(), rec.getKeyAlias(), rec.getSignature(), rec.getCreatedAt());
        } catch (AEADBadTagException e) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Wrong key password");
        } catch (GeneralSecurityException e) {
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, "Signing failed: " + e.getMessage());
        } finally {
            if (pkcs8 != null) Arrays.fill(pkcs8, (byte) 0);
        }
    }

    // ---------------------------------------------------------- VERIFY
    /**
     * Verify using either a stored key alias OR a supplied PEM public key.
     * Every outcome is written to the verification log.
     */
    public VerifyResponse verify(String documentName, byte[] data, String signatureB64,
                                 String alias, String publicKeyPem) {
        boolean hasAlias = alias != null && !alias.isBlank();
        boolean hasPem = publicKeyPem != null && !publicKeyPem.isBlank();
        if (!hasAlias && !hasPem) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Provide either 'alias' or 'publicKeyPem'");
        }

        String hash = sha256Hex(data);
        String keyLabel = hasAlias ? alias : "external-public-key";
        String algorithm = null;
        boolean valid = false;
        String message;

        try {
            PublicKey publicKey;
            if (hasAlias) {
                KeyPairEntity entity = keyService.get(alias);
                publicKey = decodePublicKey(entity.getPublicKey(), entity.getAlgorithm());
            } else {
                publicKey = parsePem(publicKeyPem);
            }
            algorithm = signatureAlgorithm(publicKey.getAlgorithm());

            byte[] sigBytes = Base64.getDecoder().decode(signatureB64.trim());
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(data);
            valid = verifier.verify(sigBytes);
            message = valid
                    ? "Signature is VALID: document is authentic and unmodified."
                    : "Signature is INVALID: document was modified or signed with a different key.";
        } catch (IllegalArgumentException e) {
            message = "Signature is not valid Base64.";
        } catch (SignatureException e) {
            message = "Signature is INVALID: malformed signature bytes.";
        } catch (ApiException e) {
            logRepo.save(buildLog(documentName, hash, keyLabel, false, e.getMessage()));
            throw e;
        } catch (GeneralSecurityException e) {
            message = "Verification error: " + e.getMessage();
        }

        logRepo.save(buildLog(documentName, hash, keyLabel, valid, message));
        return new VerifyResponse(valid, message, hash, algorithm, keyLabel);
    }

    public List<SignatureRecord> records() {
        return recordRepo.findAllByOrderByCreatedAtDesc();
    }

    public List<VerificationLog> logs() {
        return logRepo.findAllByOrderByVerifiedAtDesc();
    }

    // --------------------------------------------------------- HELPERS
    private VerificationLog buildLog(String doc, String hash, String key, boolean valid, String msg) {
        VerificationLog l = new VerificationLog();
        l.setDocumentName(doc);
        l.setDocumentHash(hash);
        l.setKeyAlias(key);
        l.setValid(valid);
        l.setMessage(msg.length() > 500 ? msg.substring(0, 500) : msg);
        return l;
    }

    private static String signatureAlgorithm(String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new ApiException(HttpStatus.BAD_REQUEST, "Unsupported key type: " + keyAlgorithm);
        };
    }

    private static PublicKey decodePublicKey(String base64Der, String algorithm) throws GeneralSecurityException {
        return KeyFactory.getInstance(algorithm)
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64Der)));
    }

    private static PublicKey parsePem(String pem) {
        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Public key PEM is not valid Base64");
        }
        for (String alg : new String[]{"RSA", "EC"}) {
            try {
                return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(der));
            } catch (GeneralSecurityException ignored) {
                // try next algorithm
            }
        }
        throw new ApiException(HttpStatus.BAD_REQUEST,
                "Unsupported or malformed public key (RSA/EC X.509 PEM expected)");
    }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
