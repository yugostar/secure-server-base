package com.security.serverbase.controller.dto;

import java.util.Set;
import java.util.UUID;

public record RegisterResponse(
        UUID id,
        String username,
        Set<String> roles
) {
}
