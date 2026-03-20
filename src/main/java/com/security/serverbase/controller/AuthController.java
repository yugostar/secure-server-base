package com.security.serverbase.controller;

import com.security.serverbase.controller.dto.*;
import com.security.serverbase.repository.AppUserRepository;
import com.security.serverbase.security.AppUser;
import com.security.serverbase.security.PasswordPolicy;
import com.security.serverbase.security.Role;
import com.security.serverbase.security.session.TokenPairService;
import jakarta.validation.Valid;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping({"/api/auth", "/auth"})
public class AuthController {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenPairService tokenPairService;

    public AuthController(AppUserRepository appUserRepository,
                          PasswordEncoder passwordEncoder,
                          TokenPairService tokenPairService) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenPairService = tokenPairService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        String username = request.username().trim();
        if (appUserRepository.existsByUsername(username)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiError("Пользователь с таким логином уже существует"));
        }

        try {
            PasswordPolicy.validateOrThrow(request.password());
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(new ApiError(ex.getMessage()));
        }

        AppUser user = new AppUser();
        user.setUsername(username);
        user.setEmail(username + "@local.test");
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(Role.USER);
        user.setAccountExpired(false);
        user.setAccountLocked(false);
        user.setCredentialsExpired(false);
        user.setDisabled(false);

        try {
            AppUser saved = appUserRepository.save(user);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(new RegisterResponse(
                            saved.getId(),
                            saved.getUsername(),
                            Set.of(saved.getRole().name())
                    ));
        } catch (DataIntegrityViolationException ex) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiError("Пользователь с таким логином уже существует"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            TokenPairResponse pair = tokenPairService.login(request.username().trim(), request.password());
            return ResponseEntity.ok(pair);
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiError("Неверный логин или пароль"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest request) {
        try {
            TokenPairResponse pair = tokenPairService.refresh(request.refreshToken());
            return ResponseEntity.ok(pair);
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiError("Refresh токен недействителен"));
        }
    }

    @GetMapping("/me")
    public MeResponse me(Authentication authentication) {
        Set<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return new MeResponse(authentication.getName(), roles);
    }
}
