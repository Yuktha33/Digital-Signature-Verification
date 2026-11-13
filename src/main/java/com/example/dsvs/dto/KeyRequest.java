package com.example.dsvs.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record KeyRequest(
        @NotBlank @Pattern(regexp = "^[A-Za-z0-9_.-]{3,50}$",
                message = "3-50 chars: letters, digits, _ . -") String alias,
        @NotBlank @Size(min = 8, message = "must be at least 8 characters") String password,
        String algorithm,   // RSA (default) or EC
        Integer keySize) {  // RSA: 2048/3072/4096, EC: 256/384
}
