package com.security.serverbase.security.jwt;

import com.security.serverbase.security.AppUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Component
public class JwtTokenProvider {

    public static final String CLAIM_TYPE = "typ";
    public static final String CLAIM_UID = "uid";
    public static final String CLAIM_SID = "sid";
    public static final String CLAIM_ROLES = "roles";

    private final JwtProperties props;
    private final SecretKey key;

    public JwtTokenProvider(JwtProperties props) {
        this.props = props;
        if (props.getSecret() == null || props.getSecret().trim().length() < 32) {
            throw new IllegalStateException("app.jwt.secret должен быть задан и иметь длину >= 32 символа");
        }
        this.key = Keys.hmacShaKeyFor(props.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(AppUser user, UUID sessionId) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(props.getAccessTtlSeconds());

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, "access");
        claims.put(CLAIM_UID, user.getId().toString());
        claims.put(CLAIM_SID, sessionId.toString());
        claims.put(CLAIM_ROLES, List.of(user.getRole().name()));

        return Jwts.builder()
                .issuer(props.getIssuer())
                .subject(user.getUsername())
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .claims().add(claims).and()
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public String generateRefreshToken(AppUser user, UUID sessionId, String refreshJti) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(props.getRefreshTtlSeconds());

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, "refresh");
        claims.put(CLAIM_UID, user.getId().toString());
        claims.put(CLAIM_SID, sessionId.toString());

        return Jwts.builder()
                .issuer(props.getIssuer())
                .subject(user.getUsername())
                .id(refreshJti)
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .claims().add(claims).and()
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Jws<Claims> parseAndValidate(String token, TokenType expectedType) {
        Jws<Claims> jws = Jwts.parser()
                .verifyWith(key)
                .requireIssuer(props.getIssuer())
                .build()
                .parseSignedClaims(token);

        TokenType actualType = getTokenType(jws.getPayload());
        if (actualType != expectedType) {
            throw new IllegalArgumentException("Неверный тип токена. Ожидался " + expectedType + ", получен " + actualType);
        }
        return jws;
    }

    public TokenType getTokenType(Claims claims) {
        Object typ = claims.get(CLAIM_TYPE);
        if (typ == null) {
            throw new IllegalArgumentException("В токене отсутствует claim 'typ'");
        }
        return switch (typ.toString()) {
            case "access" -> TokenType.ACCESS;
            case "refresh" -> TokenType.REFRESH;
            default -> throw new IllegalArgumentException("Неизвестный тип токена: " + typ);
        };
    }

    public UUID getSessionId(Claims claims) {
        Object sid = claims.get(CLAIM_SID);
        if (sid == null) {
            throw new IllegalArgumentException("В токене отсутствует claim 'sid'");
        }
        return UUID.fromString(sid.toString());
    }

    public UUID getUserId(Claims claims) {
        Object uid = claims.get(CLAIM_UID);
        if (uid == null) {
            throw new IllegalArgumentException("В токене отсутствует claim 'uid'");
        }
        return UUID.fromString(uid.toString());
    }
}
