package com.security.serverbase.license.repository;

import com.security.serverbase.license.model.Device;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface DeviceRepository extends JpaRepository<Device, UUID> {
    Optional<Device> findByMacAddress(String macAddress);
}
