package com.security.serverbase.security;

import java.util.regex.Pattern;

/**
 * Простая проверка надёжности пароля при регистрации.
 */
public final class PasswordPolicy {

    private PasswordPolicy() {
    }

    private static final int MIN_LENGTH = 8;
    private static final Pattern HAS_SPECIAL = Pattern.compile("[^a-zA-Z0-9]");
    private static final Pattern HAS_DIGIT = Pattern.compile("\\d");
    private static final Pattern HAS_LETTER = Pattern.compile("[a-zA-Z]");

    public static void validateOrThrow(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("Пароль обязателен");
        }
        if (rawPassword.length() < MIN_LENGTH) {
            throw new IllegalArgumentException("Пароль слишком короткий (минимум " + MIN_LENGTH + " символов)");
        }
        if (!HAS_LETTER.matcher(rawPassword).find()) {
            throw new IllegalArgumentException("Пароль должен содержать хотя бы одну букву");
        }
        if (!HAS_DIGIT.matcher(rawPassword).find()) {
            throw new IllegalArgumentException("Пароль должен содержать хотя бы одну цифру");
        }
        if (!HAS_SPECIAL.matcher(rawPassword).find()) {
            throw new IllegalArgumentException("Пароль должен содержать хотя бы один спецсимвол");
        }
    }
}
