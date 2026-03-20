package com.security.serverbase.security;

import com.security.serverbase.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BootstrapAdminRunner implements ApplicationRunner {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.security.bootstrap-admin.username:}")
    private String adminUsername;

    @Value("${app.security.bootstrap-admin.password:}")
    private String adminPassword;

    public BootstrapAdminRunner(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (adminUsername == null || adminUsername.isBlank() || adminPassword == null || adminPassword.isBlank()) {
            return;
        }
        if (appUserRepository.existsByUsername(adminUsername.trim())) {
            return;
        }

        PasswordPolicy.validateOrThrow(adminPassword);

        AppUser admin = new AppUser();
        admin.setUsername(adminUsername.trim());
        admin.setEmail(adminUsername.trim() + "@local.test");
        admin.setPasswordHash(passwordEncoder.encode(adminPassword));
        admin.setRole(Role.ADMIN);
        admin.setAccountExpired(false);
        admin.setAccountLocked(false);
        admin.setCredentialsExpired(false);
        admin.setDisabled(false);
        appUserRepository.save(admin);
    }
}
