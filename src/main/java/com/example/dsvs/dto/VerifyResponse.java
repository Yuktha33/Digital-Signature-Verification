package com.example.dsvs.dto;

public record VerifyResponse(boolean valid, String message, String documentHash,
                             String algorithm, String keyAlias) {
}
