package com.security.serverbase.controller.dto;

import java.util.List;
import java.util.UUID;

public record UserSummaryResponse(
        UUID id,
        String username,
        boolean enabled,
        List<String> roles
) {
}
