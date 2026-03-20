package com.security.serverbase.license.repository;

import com.security.serverbase.license.model.Device;
import com.security.serverbase.license.model.DeviceLicense;
import com.security.serverbase.license.model.License;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface DeviceLicenseRepository extends JpaRepository<DeviceLicense, UUID> {
    Optional<DeviceLicense> findByLicenseAndDevice(License license, Device device);

    @Query("select count(dl) from DeviceLicense dl where dl.license.id = :licenseId")
    long countByLicenseId(@Param("licenseId") UUID licenseId);
}
