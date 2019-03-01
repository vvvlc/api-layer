package com.broadcom.apiml.security.service.service;

public class TokenValidationResult {
    private final boolean valid;

    public TokenValidationResult(boolean valid) {
        this.valid = valid;
    }

    public boolean isValid() {
        return this.valid;
    }
}
