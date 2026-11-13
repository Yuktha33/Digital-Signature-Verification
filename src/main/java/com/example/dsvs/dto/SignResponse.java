package com.example.dsvs.dto;

import java.time.Instant;

public record SignResponse(Long recordId, String documentName, String documentHash,
                           String algorithm, String keyAlias, String signature, Instant createdAt) {
}
