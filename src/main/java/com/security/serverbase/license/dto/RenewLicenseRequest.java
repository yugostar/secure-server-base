package com.security.serverbase.license.dto;

import jakarta.validation.constraints.NotBlank;

public record RenewLicenseRequest(
        @NotBlank String activationKey
) {
}
