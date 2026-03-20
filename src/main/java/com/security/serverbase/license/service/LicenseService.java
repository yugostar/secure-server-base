package com.security.serverbase.license.service;

import com.security.serverbase.license.dto.*;
import com.security.serverbase.license.model.*;
import com.security.serverbase.license.repository.*;
import com.security.serverbase.security.AppUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.UUID;

@Service
public class LicenseService {

    private final ApplicationUserService applicationUserService;
    private final ProductService productService;
    private final LicenseTypeService licenseTypeService;
    private final LicenseRepository licenseRepository;
    private final DeviceRepository deviceRepository;
    private final DeviceLicenseRepository deviceLicenseRepository;
    private final LicenseHistoryRepository licenseHistoryRepository;
    private final TicketSignatureService ticketSignatureService;

    @Value("${app.ticket.ttl-seconds:300}")
    private long ticketTtlSeconds;

    public LicenseService(ApplicationUserService applicationUserService,
                          ProductService productService,
                          LicenseTypeService licenseTypeService,
                          LicenseRepository licenseRepository,
                          DeviceRepository deviceRepository,
                          DeviceLicenseRepository deviceLicenseRepository,
                          LicenseHistoryRepository licenseHistoryRepository,
                          TicketSignatureService ticketSignatureService) {
        this.applicationUserService = applicationUserService;
        this.productService = productService;
        this.licenseTypeService = licenseTypeService;
        this.licenseRepository = licenseRepository;
        this.deviceRepository = deviceRepository;
        this.deviceLicenseRepository = deviceLicenseRepository;
        this.licenseHistoryRepository = licenseHistoryRepository;
        this.ticketSignatureService = ticketSignatureService;
    }

    @Transactional
    public CreateLicenseResponse createLicense(CreateLicenseRequest request, UUID adminId) {
        Product product = productService.getProductOrFail(request.productId());
        LicenseType type = licenseTypeService.getTypeOrFail(request.typeId());
        AppUser owner = applicationUserService.getActiveUserOrFail(request.ownerId());
        AppUser admin = applicationUserService.getActiveUserOrFail(adminId);

        License license = new License();
        license.setCode(generateCode());
        license.setProduct(product);
        license.setType(type);
        license.setOwner(owner);
        license.setUser(null);
        license.setBlocked(Boolean.TRUE.equals(request.blocked()));
        license.setDeviceCount(request.deviceCount() == null ? 1 : request.deviceCount());
        license.setDescription(request.description());

        License saved = licenseRepository.save(license);
        saveHistory(saved, admin, "CREATED", "Лицензия создана администратором");
        return toCreateResponse(saved);
    }

    @Transactional
    public TicketResponse activateLicense(ActivateLicenseRequest request, UUID userId) {
        AppUser user = applicationUserService.getActiveUserOrFail(userId);
        License license = licenseRepository.findByCode(request.activationKey())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Лицензия не найдена"));

        if (license.getUser() != null && !license.getUser().getId().equals(userId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Лицензия принадлежит другому пользователю");
        }

        Device device = deviceRepository.findByMacAddress(normalizeMac(request.deviceMac()))
                .orElseGet(() -> createDevice(user, request.deviceName(), request.deviceMac()));

        if (license.getFirstActivationDate() == null) {
            Instant now = Instant.now();
            license.setUser(user);
            license.setFirstActivationDate(now);
            license.setEndingDate(now.plus(license.getType().getDefaultDurationInDays(), ChronoUnit.DAYS));
            licenseRepository.save(license);
            createDeviceLicenseIfMissing(license, device);
            saveHistory(license, user, "ACTIVATED", "Первая активация лицензии");
            return buildSignedTicketResponse(license, device);
        }

        if (deviceLicenseRepository.findByLicenseAndDevice(license, device).isEmpty()) {
            long currentLinkedDevices = deviceLicenseRepository.countByLicenseId(license.getId());
            if (currentLinkedDevices >= license.getDeviceCount()) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Достигнут лимит устройств для лицензии");
            }
            createDeviceLicenseIfMissing(license, device);
        }

        saveHistory(license, user, "ACTIVATED", "Повторная активация лицензии на устройстве");
        return buildSignedTicketResponse(license, device);
    }

    @Transactional(readOnly = true)
    public TicketResponse checkLicense(CheckLicenseRequest request, UUID userId) {
        Device device = deviceRepository.findByMacAddress(normalizeMac(request.deviceMac()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Устройство не найдено"));

        License license = licenseRepository.findActiveByDeviceUserAndProduct(device.getId(), userId, request.productId(), Instant.now())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Активная лицензия не найдена"));

        return buildSignedTicketResponse(license, device);
    }

    @Transactional
    public TicketResponse renewLicense(RenewLicenseRequest request, UUID userId) {
        AppUser user = applicationUserService.getActiveUserOrFail(userId);
        License license = licenseRepository.findByCode(request.activationKey())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Лицензия не найдена"));

        if (license.getUser() != null && !license.getUser().getId().equals(userId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Лицензия принадлежит другому пользователю");
        }

        Instant now = Instant.now();
        if (!isRenewalAllowed(license, now)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Продление пока недоступно");
        }

        Instant base = license.getEndingDate() == null || license.getEndingDate().isBefore(now) ? now : license.getEndingDate();
        license.setEndingDate(base.plus(license.getType().getDefaultDurationInDays(), ChronoUnit.DAYS));
        License saved = licenseRepository.save(license);
        saveHistory(saved, user, "RENEWED", "Лицензия продлена пользователем");

        Device device = resolveAnyDevice(saved);
        return buildSignedTicketResponse(saved, device);
    }

    private boolean isRenewalAllowed(License license, Instant now) {
        if (license.getEndingDate() == null) {
            return true;
        }
        if (license.getEndingDate().isBefore(now)) {
            return true;
        }
        return !license.getEndingDate().isAfter(now.plus(7, ChronoUnit.DAYS));
    }

    private Device resolveAnyDevice(License license) {
        return deviceLicenseRepository.findAll().stream()
                .filter(dl -> dl.getLicense().getId().equals(license.getId()))
                .map(DeviceLicense::getDevice)
                .findFirst()
                .orElseGet(() -> {
                    Device device = new Device();
                    device.setName("virtual-device");
                    device.setMacAddress("virtual-" + license.getId());
                    device.setUser(license.getUser() != null ? license.getUser() : license.getOwner());
                    return device;
                });
    }

    private CreateLicenseResponse toCreateResponse(License license) {
        return new CreateLicenseResponse(
                license.getId(),
                license.getCode(),
                license.getOwner() != null ? license.getOwner().getId() : null,
                license.getUser() != null ? license.getUser().getId() : null,
                license.getProduct().getId(),
                license.getType().getId(),
                license.getDeviceCount(),
                license.isBlocked(),
                license.getDescription(),
                license.getFirstActivationDate(),
                license.getEndingDate()
        );
    }

    private Device createDevice(AppUser user, String deviceName, String deviceMac) {
        Device device = new Device();
        device.setUser(user);
        device.setName(deviceName.trim());
        device.setMacAddress(normalizeMac(deviceMac));
        return deviceRepository.save(device);
    }

    private void createDeviceLicenseIfMissing(License license, Device device) {
        if (deviceLicenseRepository.findByLicenseAndDevice(license, device).isPresent()) {
            return;
        }
        DeviceLicense relation = new DeviceLicense();
        relation.setLicense(license);
        relation.setDevice(device);
        relation.setActivationDate(Instant.now());
        deviceLicenseRepository.save(relation);
    }

    private void saveHistory(License license, AppUser user, String status, String description) {
        LicenseHistory history = new LicenseHistory();
        history.setLicense(license);
        history.setUser(user);
        history.setStatus(status);
        history.setDescription(description);
        history.setChangeDate(Instant.now());
        licenseHistoryRepository.save(history);
    }

    private TicketResponse buildSignedTicketResponse(License license, Device device) {
        Ticket ticket = new Ticket(
                Instant.now(),
                ticketTtlSeconds,
                license.getFirstActivationDate(),
                license.getEndingDate(),
                license.getUser() != null ? license.getUser().getId() : null,
                device != null ? device.getId() : null,
                license.isBlocked()
        );
        return new TicketResponse(ticket, ticketSignatureService.sign(ticket));
    }

    private String generateCode() {
        return "LIC-" + UUID.randomUUID().toString().replace("-", "").toUpperCase(Locale.ROOT);
    }

    private String normalizeMac(String mac) {
        return mac.trim().toUpperCase(Locale.ROOT);
    }
}
