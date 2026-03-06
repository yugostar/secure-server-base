package com.security.serverbase.security;

import com.security.serverbase.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

/**
 * Создаёт администратора при запуске, если заданы переменные окружения:
 * - APP_ADMIN_USERNAME
 * - APP_ADMIN_PASSWORD
 *
 * Это позволяет тестировать роль ADMIN, при этом не добавляя пользователей "в явном виде" в код/скрипты.
 */
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

        if (appUserRepository.existsByUsername(adminUsername)) {
            return;
        }

        // Проверим политику пароля, чтобы админ тоже соответствовал требованиям.
        PasswordPolicy.validateOrThrow(adminPassword);

        AppUser admin = new AppUser();
        admin.setUsername(adminUsername.trim());
        admin.setPasswordHash(passwordEncoder.encode(adminPassword));
        admin.setRoles(new HashSet<>(Set.of(Role.ADMIN)));
        admin.setEnabled(true);
        appUserRepository.save(admin);
    }
}
