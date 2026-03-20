package com.security.serverbase.security.session;

import com.security.serverbase.controller.dto.TokenPairResponse;
import com.security.serverbase.repository.AppUserRepository;
import com.security.serverbase.repository.UserSessionRepository;
import com.security.serverbase.security.AppUser;
import com.security.serverbase.security.jwt.JwtProperties;
import com.security.serverbase.security.jwt.JwtTokenProvider;
import com.security.serverbase.security.jwt.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class TokenPairService {

    private final AuthenticationManager authenticationManager;
    private final AppUserRepository userRepository;
    private final UserSessionRepository sessionRepository;
    private final JwtTokenProvider tokenProvider;
    private final JwtProperties props;

    public TokenPairService(AuthenticationManager authenticationManager,
                            AppUserRepository userRepository,
                            UserSessionRepository sessionRepository,
                            JwtTokenProvider tokenProvider,
                            JwtProperties props) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.tokenProvider = tokenProvider;
        this.props = props;
    }

    @Transactional
    public TokenPairResponse login(String username, String password) {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        AppUser user = userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        UUID sessionId = UUID.randomUUID();
        String refreshJti = UUID.randomUUID().toString();
        Instant refreshExp = Instant.now().plusSeconds(props.getRefreshTtlSeconds());

        UserSession session = new UserSession(sessionId, user, refreshJti, refreshExp);
        session.setStatus(SessionStatus.ACTIVE);
        session.setLastUsedAt(Instant.now());
        sessionRepository.save(session);

        String access = tokenProvider.generateAccessToken(user, sessionId);
        String refresh = tokenProvider.generateRefreshToken(user, sessionId, refreshJti);

        return new TokenPairResponse(access, refresh, "Bearer",
                props.getAccessTtlSeconds(), props.getRefreshTtlSeconds());
    }

    @Transactional
    public TokenPairResponse refresh(String refreshToken) {
        Jws<Claims> jws = tokenProvider.parseAndValidate(refreshToken, TokenType.REFRESH);
        Claims claims = jws.getPayload();

        UUID sessionId = tokenProvider.getSessionId(claims);
        UUID userId = tokenProvider.getUserId(claims);
        String refreshJti = claims.getId();

        UserSession session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new IllegalArgumentException("Session not found"));

        if (session.getUser() == null || session.getUser().getId() == null || !session.getUser().getId().equals(userId)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        if (session.getRefreshExpiresAt() != null && session.getRefreshExpiresAt().isBefore(Instant.now())) {
            session.setStatus(SessionStatus.EXPIRED);
            sessionRepository.save(session);
            throw new IllegalArgumentException("Refresh token expired");
        }

        if (session.getStatus() == SessionStatus.ACTIVE) {
            if (!refreshJti.equals(session.getRefreshJti())) {
                session.setStatus(SessionStatus.COMPROMISED);
                sessionRepository.save(session);
                throw new IllegalArgumentException("Refresh token reuse detected");
            }

            session.setStatus(SessionStatus.REVOKED);
            session.setRevokedAt(Instant.now());

            AppUser user = session.getUser();

            UUID newSessionId = UUID.randomUUID();
            String newRefreshJti = UUID.randomUUID().toString();
            Instant newRefreshExp = Instant.now().plusSeconds(props.getRefreshTtlSeconds());

            UserSession newSession = new UserSession(newSessionId, user, newRefreshJti, newRefreshExp);
            newSession.setStatus(SessionStatus.ACTIVE);
            newSession.setLastUsedAt(Instant.now());

            session.setReplacedBySessionId(newSessionId);

            sessionRepository.save(session);
            sessionRepository.save(newSession);

            String access = tokenProvider.generateAccessToken(user, newSessionId);
            String refresh = tokenProvider.generateRefreshToken(user, newSessionId, newRefreshJti);

            return new TokenPairResponse(access, refresh, "Bearer",
                    props.getAccessTtlSeconds(), props.getRefreshTtlSeconds());
        }

        if (session.getStatus() == SessionStatus.REVOKED && refreshJti.equals(session.getRefreshJti())) {
            session.setStatus(SessionStatus.COMPROMISED);
            sessionRepository.save(session);
        }
        throw new IllegalArgumentException("Refresh token is not active");
    }
}
