package com.security.serverbase.license.model;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "device_license",
        uniqueConstraints = @UniqueConstraint(name = "uk_device_license_pair", columnNames = {"license_id", "device_id"}))
public class DeviceLicense {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "license_id", nullable = false)
    private License license;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "device_id", nullable = false)
    private Device device;

    @Column(name = "activation_date", nullable = false)
    private Instant activationDate;

    @PrePersist
    public void onCreate() {
        if (activationDate == null) {
            activationDate = Instant.now();
        }
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public License getLicense() {
        return license;
    }

    public void setLicense(License license) {
        this.license = license;
    }

    public Device getDevice() {
        return device;
    }

    public void setDevice(Device device) {
        this.device = device;
    }

    public Instant getActivationDate() {
        return activationDate;
    }

    public void setActivationDate(Instant activationDate) {
        this.activationDate = activationDate;
    }
}
