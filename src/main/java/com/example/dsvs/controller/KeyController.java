package com.example.dsvs.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.dsvs.dto.KeyRequest;
import com.example.dsvs.dto.KeyResponse;
import com.example.dsvs.service.KeyService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    private final KeyService keyService;

    public KeyController(KeyService keyService) {
        this.keyService = keyService;
    }

    @PostMapping
    public ResponseEntity<KeyResponse> generate(@Valid @RequestBody KeyRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(keyService.generate(request));
    }

    @GetMapping
    public List<KeyResponse> list() {
        return keyService.list();
    }

    @GetMapping("/{alias}")
    public KeyResponse get(@PathVariable String alias) {
        return keyService.getPublic(alias);
    }

    /** Download the public key as a .pem file so others can verify your signatures. */
    @GetMapping(value = "/{alias}/public", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> publicPem(@PathVariable String alias) {
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + alias + "-public.pem\"")
                .body(keyService.getPublic(alias).publicKeyPem());
    }

    @DeleteMapping("/{alias}")
    public Map<String, String> delete(@PathVariable String alias) {
        keyService.delete(alias);
        return Map.of("message", "Key deleted: " + alias);
    }
}
