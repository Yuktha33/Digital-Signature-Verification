package com.example.dsvs.service;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.example.dsvs.dto.KeyRequest;
import com.example.dsvs.dto.KeyResponse;
import com.example.dsvs.entity.KeyPairEntity;
import com.example.dsvs.exception.ApiException;
import com.example.dsvs.repository.KeyPairRepository;

@Service
public class KeyService {

    private static final Set<Integer> RSA_SIZES = Set.of(2048, 3072, 4096);
    private static final Set<Integer> EC_SIZES = Set.of(256, 384);

    private final KeyPairRepository repository;
    private final KeyProtectionService protection;

    public KeyService(KeyPairRepository repository, KeyProtectionService protection) {
        this.repository = repository;
        this.protection = protection;
    }

    public KeyResponse generate(KeyRequest req) {
        String algorithm = req.algorithm() == null || req.algorithm().isBlank()
                ? "RSA" : req.algorithm().toUpperCase(Locale.ROOT);

        if (!algorithm.equals("RSA") && !algorithm.equals("EC")) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "algorithm must be RSA or EC");
        }
        int keySize = req.keySize() != null ? req.keySize() : (algorithm.equals("RSA") ? 2048 : 256);
        if (algorithm.equals("RSA") && !RSA_SIZES.contains(keySize)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "RSA keySize must be 2048, 3072 or 4096");
        }
        if (algorithm.equals("EC") && !EC_SIZES.contains(keySize)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "EC keySize must be 256 or 384");
        }
        if (repository.existsByAlias(req.alias())) {
            throw new ApiException(HttpStatus.CONFLICT, "Alias already exists: " + req.alias());
        }

        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm);
            if (algorithm.equals("RSA")) {
                gen.initialize(keySize);
            } else {
                gen.initialize(new ECGenParameterSpec(keySize == 384 ? "secp384r1" : "secp256r1"));
            }
            KeyPair pair = gen.generateKeyPair();

            byte[] pkcs8 = pair.getPrivate().getEncoded();
            KeyProtectionService.Protected prot = protection.encrypt(pkcs8, req.password().toCharArray());
            Arrays.fill(pkcs8, (byte) 0);

            KeyPairEntity e = new KeyPairEntity();
            e.setAlias(req.alias());
            e.setAlgorithm(algorithm);
            e.setKeySize(keySize);
            e.setPublicKey(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
            e.setEncryptedPrivateKey(prot.cipherB64());
            e.setSalt(prot.saltB64());
            e.setIv(prot.ivB64());
            return toResponse(repository.save(e));
        } catch (GeneralSecurityException ex) {
            throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, "Key generation failed: " + ex.getMessage());
        }
    }

    public List<KeyResponse> list() {
        return repository.findAll().stream().map(this::toResponse).toList();
    }

    public KeyPairEntity get(String alias) {
        return repository.findByAlias(alias)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Key not found: " + alias));
    }

    public KeyResponse getPublic(String alias) {
        return toResponse(get(alias));
    }

    public void delete(String alias) {
        repository.delete(get(alias));
    }

    public static String toPem(String base64Der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(Base64.getDecoder().decode(base64Der));
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n";
    }

    private KeyResponse toResponse(KeyPairEntity e) {
        return new KeyResponse(e.getId(), e.getAlias(), e.getAlgorithm(), e.getKeySize(),
                toPem(e.getPublicKey()), e.getCreatedAt());
    }
}
