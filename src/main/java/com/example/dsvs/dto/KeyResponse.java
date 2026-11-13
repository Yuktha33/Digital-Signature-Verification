package com.example.dsvs.dto;

import java.time.Instant;

public record KeyResponse(Long id, String alias, String algorithm, int keySize,
                          String publicKeyPem, Instant createdAt) {
}
