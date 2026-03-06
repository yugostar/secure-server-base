package com.security.serverbase.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Логин обязателен")
        @Size(min = 3, max = 100, message = "Логин должен быть длиной 3-100 символов")
        String username,

        @NotBlank(message = "Пароль обязателен")
        @Size(min = 8, max = 128, message = "Пароль должен быть длиной 8-128 символов")
        String password
) {
}
