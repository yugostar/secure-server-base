package com.security.serverbase.controller.dto;

import java.util.Set;

public record RegisterResponse(
        Long id,
        String username,
        Set<String> roles
) {
}
