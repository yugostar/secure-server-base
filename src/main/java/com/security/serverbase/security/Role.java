package com.security.serverbase.security;

/**
 * Роли приложения.
 *
 * В Spring Security они будут преобразованы в GrantedAuthority с префиксом "ROLE_".
 */
public enum Role {
    USER,
    ADMIN
}
