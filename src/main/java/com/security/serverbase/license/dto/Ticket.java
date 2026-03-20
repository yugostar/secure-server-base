package com.security.serverbase.license.dto;

import java.time.Instant;
import java.util.UUID;

public record Ticket(
        Instant serverDate,
        long ticketTtlSeconds,
        Instant activationDate,
        Instant endingDate,
        UUID userId,
        UUID deviceId,
        boolean blocked
) {
}
