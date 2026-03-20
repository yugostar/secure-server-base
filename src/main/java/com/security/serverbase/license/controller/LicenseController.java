package com.security.serverbase.license.controller;

import com.security.serverbase.license.dto.*;
import com.security.serverbase.license.service.ApplicationUserService;
import com.security.serverbase.license.service.LicenseService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/licenses")
public class LicenseController {

    private final LicenseService licenseService;
    private final ApplicationUserService applicationUserService;

    public LicenseController(LicenseService licenseService, ApplicationUserService applicationUserService) {
        this.licenseService = licenseService;
        this.applicationUserService = applicationUserService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CreateLicenseResponse createLicense(@Valid @RequestBody CreateLicenseRequest request,
                                               Authentication authentication) {
        var admin = applicationUserService.getByUsernameOrFail(authentication.getName());
        return licenseService.createLicense(request, admin.getId());
    }

    @PostMapping("/activate")
    public TicketResponse activateLicense(@Valid @RequestBody ActivateLicenseRequest request,
                                          Authentication authentication) {
        var user = applicationUserService.getByUsernameOrFail(authentication.getName());
        return licenseService.activateLicense(request, user.getId());
    }

    @PostMapping("/check")
    public TicketResponse checkLicense(@Valid @RequestBody CheckLicenseRequest request,
                                       Authentication authentication) {
        var user = applicationUserService.getByUsernameOrFail(authentication.getName());
        return licenseService.checkLicense(request, user.getId());
    }

    @PostMapping("/renew")
    public TicketResponse renewLicense(@Valid @RequestBody RenewLicenseRequest request,
                                       Authentication authentication) {
        var user = applicationUserService.getByUsernameOrFail(authentication.getName());
        return licenseService.renewLicense(request, user.getId());
    }
}
