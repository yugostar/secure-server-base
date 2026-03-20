package com.security.serverbase.license.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record CheckLicenseRequest(
        @NotBlank String deviceMac,
        @NotNull UUID productId
) {
}
