package com.security.serverbase.repository;

import com.security.serverbase.security.session.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {
    Optional<UserSession> findByIdAndUserId(UUID id, UUID userId);
}
