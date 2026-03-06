package com.security.serverbase.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Удобная конечная точка для получения CSRF токена.
 *
 * При обращении к /api/csrf Spring Security также выставит cookie "XSRF-TOKEN".
 */
@RestController
public class CsrfController {

    @GetMapping("/api/csrf")
    public CsrfToken csrf(CsrfToken token) {
        return token;
    }
}
