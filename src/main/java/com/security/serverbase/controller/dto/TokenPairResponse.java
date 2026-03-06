package com.security.serverbase.controller.dto;

public record TokenPairResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long accessExpiresInSeconds,
        long refreshExpiresInSeconds
) {
}
