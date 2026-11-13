package com.example.dsvs;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.dsvs.dto.KeyRequest;
import com.example.dsvs.dto.KeyResponse;
import com.example.dsvs.dto.SignResponse;
import com.example.dsvs.dto.VerifyResponse;
import com.example.dsvs.exception.ApiException;
import com.example.dsvs.service.KeyService;
import com.example.dsvs.service.SignatureService;

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:testdb")
class SignatureServiceTest {

    @Autowired KeyService keyService;
    @Autowired SignatureService signatureService;

    private static final byte[] DOC = "Contract: pay 100 USD".getBytes(StandardCharsets.UTF_8);

    @Test
    void rsaSignAndVerify() {
        keyService.generate(new KeyRequest("rsa-test", "StrongPass1!", "RSA", 2048));
        SignResponse s = signatureService.sign("c.txt", DOC, "rsa-test", "StrongPass1!");

        assertTrue(signatureService.verify("c.txt", DOC, s.signature(), "rsa-test", null).valid());
    }

    @Test
    void ecdsaSignAndVerifyWithExternalPem() {
        KeyResponse k = keyService.generate(new KeyRequest("ec-test", "StrongPass1!", "EC", 256));
        SignResponse s = signatureService.sign("c.txt", DOC, "ec-test", "StrongPass1!");

        VerifyResponse r = signatureService.verify("c.txt", DOC, s.signature(), null, k.publicKeyPem());
        assertTrue(r.valid());
        assertEquals("SHA256withECDSA", r.algorithm());
    }

    @Test
    void tamperedDocumentIsRejected() {
        keyService.generate(new KeyRequest("tamper-test", "StrongPass1!", "RSA", 2048));
        SignResponse s = signatureService.sign("c.txt", DOC, "tamper-test", "StrongPass1!");

        byte[] tampered = "Contract: pay 900 USD".getBytes(StandardCharsets.UTF_8);
        assertFalse(signatureService.verify("c.txt", tampered, s.signature(), "tamper-test", null).valid());
    }

    @Test
    void wrongKeyIsRejected() {
        keyService.generate(new KeyRequest("key-a", "StrongPass1!", "RSA", 2048));
        keyService.generate(new KeyRequest("key-b", "StrongPass1!", "RSA", 2048));
        SignResponse s = signatureService.sign("c.txt", DOC, "key-a", "StrongPass1!");

        assertFalse(signatureService.verify("c.txt", DOC, s.signature(), "key-b", null).valid());
    }

    @Test
    void wrongPasswordCannotSign() {
        keyService.generate(new KeyRequest("pw-test", "StrongPass1!", "RSA", 2048));
        assertThrows(ApiException.class, () -> signatureService.sign("c.txt", DOC, "pw-test", "WrongPass123"));
    }

    @Test
    void garbageSignatureIsInvalidNotError() {
        keyService.generate(new KeyRequest("garbage-test", "StrongPass1!", "RSA", 2048));
        assertFalse(signatureService.verify("c.txt", DOC, "not base64 !!", "garbage-test", null).valid());
    }
}
