package com.security.serverbase.license.repository;

import com.security.serverbase.license.model.LicenseType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface LicenseTypeRepository extends JpaRepository<LicenseType, UUID> {
}
