package com.security.serverbase.license.dto;

import jakarta.validation.constraints.NotBlank;

public record ActivateLicenseRequest(
        @NotBlank String activationKey,
        @NotBlank String deviceMac,
        @NotBlank String deviceName
) {
}
