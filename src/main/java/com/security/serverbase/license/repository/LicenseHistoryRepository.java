package com.security.serverbase.license.repository;

import com.security.serverbase.license.model.LicenseHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface LicenseHistoryRepository extends JpaRepository<LicenseHistory, UUID> {
}
