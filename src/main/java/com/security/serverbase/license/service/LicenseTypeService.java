package com.security.serverbase.license.service;

import com.security.serverbase.license.model.LicenseType;
import com.security.serverbase.license.repository.LicenseTypeRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class LicenseTypeService {

    private final LicenseTypeRepository licenseTypeRepository;

    public LicenseTypeService(LicenseTypeRepository licenseTypeRepository) {
        this.licenseTypeRepository = licenseTypeRepository;
    }

    public LicenseType getTypeOrFail(UUID id) {
        return licenseTypeRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Тип лицензии не найден"));
    }
}
