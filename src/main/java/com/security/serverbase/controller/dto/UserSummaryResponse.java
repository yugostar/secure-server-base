package com.security.serverbase.controller.dto;

import java.util.List;

public record UserSummaryResponse(
        Long id,
        String username,
        boolean enabled,
        List<String> roles
) {
}
