package com.example.dsvs.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.example.dsvs.dto.SignResponse;
import com.example.dsvs.dto.VerifyResponse;
import com.example.dsvs.entity.SignatureRecord;
import com.example.dsvs.entity.VerificationLog;
import com.example.dsvs.service.SignatureService;

@RestController
@RequestMapping("/api")
public class SignatureController {

    private final SignatureService signatureService;

    public SignatureController(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    @PostMapping(value = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public SignResponse sign(@RequestParam("file") MultipartFile file,
                             @RequestParam("alias") String alias,
                             @RequestParam("password") String password) throws IOException {
        return signatureService.sign(file.getOriginalFilename(), file.getBytes(), alias, password);
    }

    @PostMapping(value = "/verify", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public VerifyResponse verify(@RequestParam("file") MultipartFile file,
                                 @RequestParam("signature") String signature,
                                 @RequestParam(value = "alias", required = false) String alias,
                                 @RequestParam(value = "publicKeyPem", required = false) String publicKeyPem)
            throws IOException {
        return signatureService.verify(file.getOriginalFilename(), file.getBytes(), signature, alias, publicKeyPem);
    }

    @GetMapping("/signatures")
    public List<SignatureRecord> signatures() {
        return signatureService.records();
    }

    @GetMapping("/verifications")
    public List<VerificationLog> verifications() {
        return signatureService.logs();
    }
}
