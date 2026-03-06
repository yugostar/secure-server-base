package com.security.serverbase.security.session;

import com.security.serverbase.security.AppUser;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Сессия пользователя для работы с refresh токенами (Assignment 5).
 *
 * Идея: каждая сессия хранит актуальный refresh jti. При обновлении (refresh) происходит ротация:
 * старая сессия -> REVOKED, создаётся новая ACTIVE.
 * Повторное использование старого refresh приводит к COMPROMISED.
 */
@Entity
@Table(name = "user_sessions")
public class UserSession {

    @Id
    @Column(columnDefinition = "uuid")
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SessionStatus status = SessionStatus.ACTIVE;

    /**
     * JTI (id) refresh токена, который сейчас является актуальным для этой сессии.
     */
    @Column(name = "refresh_jti", nullable = false, unique = true, length = 64)
    private String refreshJti;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_used_at", nullable = false)
    private Instant lastUsedAt;

    @Column(name = "refresh_expires_at", nullable = false)
    private Instant refreshExpiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "replaced_by_session_id", columnDefinition = "uuid")
    private UUID replacedBySessionId;

    public UserSession() {
    }

    public UserSession(UUID id, AppUser user, String refreshJti, Instant refreshExpiresAt) {
        this.id = id;
        this.user = user;
        this.refreshJti = refreshJti;
        this.refreshExpiresAt = refreshExpiresAt;
    }

    @PrePersist
    public void onCreate() {
        Instant now = Instant.now();
        if (createdAt == null) createdAt = now;
        if (lastUsedAt == null) lastUsedAt = now;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public AppUser getUser() {
        return user;
    }

    public void setUser(AppUser user) {
        this.user = user;
    }

    public SessionStatus getStatus() {
        return status;
    }

    public void setStatus(SessionStatus status) {
        this.status = status;
    }

    public String getRefreshJti() {
        return refreshJti;
    }

    public void setRefreshJti(String refreshJti) {
        this.refreshJti = refreshJti;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }

    public void setLastUsedAt(Instant lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    public Instant getRefreshExpiresAt() {
        return refreshExpiresAt;
    }

    public void setRefreshExpiresAt(Instant refreshExpiresAt) {
        this.refreshExpiresAt = refreshExpiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }

    public UUID getReplacedBySessionId() {
        return replacedBySessionId;
    }

    public void setReplacedBySessionId(UUID replacedBySessionId) {
        this.replacedBySessionId = replacedBySessionId;
    }
}
