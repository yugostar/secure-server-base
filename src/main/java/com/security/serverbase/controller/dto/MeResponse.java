package com.security.serverbase.controller.dto;

import java.util.Set;

public record MeResponse(
        String username,
        Set<String> roles
) {
}
