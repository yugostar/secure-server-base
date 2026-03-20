package com.security.serverbase.license.service;

import com.security.serverbase.repository.AppUserRepository;
import com.security.serverbase.security.AppUser;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class ApplicationUserService {

    private final AppUserRepository appUserRepository;

    public ApplicationUserService(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    public AppUser getActiveUserOrFail(UUID userId) {
        AppUser user = appUserRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
        if (user.isDisabled() || user.isAccountExpired() || user.isAccountLocked() || user.isCredentialsExpired()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь недоступен");
        }
        return user;
    }

    public AppUser getByUsernameOrFail(String username) {
        return appUserRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
    }
}
