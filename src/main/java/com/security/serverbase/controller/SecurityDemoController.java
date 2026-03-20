package com.security.serverbase.controller;

import com.security.serverbase.controller.dto.UserSummaryResponse;
import com.security.serverbase.repository.AppUserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api")
public class SecurityDemoController {

    private final AppUserRepository appUserRepository;

    public SecurityDemoController(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @GetMapping("/demo/user")
    public String userZone(Authentication authentication) {
        return "Доступ разрешён. Текущий пользователь: " + authentication.getName();
    }

    @GetMapping("/admin/users")
    public List<UserSummaryResponse> listUsers() {
        return appUserRepository.findAll().stream()
                .map(user -> new UserSummaryResponse(
                        user.getId(),
                        user.getUsername(),
                        user.isEnabled(),
                        List.of(user.getRole().name())
                ))
                .toList();
    }
}
