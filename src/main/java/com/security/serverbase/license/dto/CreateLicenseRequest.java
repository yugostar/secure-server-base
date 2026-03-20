package com.security.serverbase.license.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record CreateLicenseRequest(
        @NotNull UUID productId,
        @NotNull UUID typeId,
        @NotNull UUID ownerId,
        @Min(1) Integer deviceCount,
        Boolean blocked,
        String description
) {
}
