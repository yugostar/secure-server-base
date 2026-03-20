package com.security.serverbase.license.dto;

import java.time.Instant;
import java.util.UUID;

public record CreateLicenseResponse(
        UUID id,
        String code,
        UUID ownerId,
        UUID userId,
        UUID productId,
        UUID typeId,
        Integer deviceCount,
        boolean blocked,
        String description,
        Instant firstActivationDate,
        Instant endingDate
) {
}
