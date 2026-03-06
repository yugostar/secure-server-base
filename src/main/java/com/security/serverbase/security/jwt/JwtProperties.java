package com.security.serverbase.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Настройки JWT (Assignment 5).
 */
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    /**
     * Секрет для подписи (HS256/HS512). Рекомендуется передавать через env JWT_SECRET.
     */
    private String secret;

    /** Issuer (iss) */
    private String issuer = "airline-system";

    /** Время жизни access token (секунды). */
    private long accessTtlSeconds = 600;

    /** Время жизни refresh token (секунды). */
    private long refreshTtlSeconds = 604800;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public long getAccessTtlSeconds() {
        return accessTtlSeconds;
    }

    public void setAccessTtlSeconds(long accessTtlSeconds) {
        this.accessTtlSeconds = accessTtlSeconds;
    }

    public long getRefreshTtlSeconds() {
        return refreshTtlSeconds;
    }

    public void setRefreshTtlSeconds(long refreshTtlSeconds) {
        this.refreshTtlSeconds = refreshTtlSeconds;
    }
}
