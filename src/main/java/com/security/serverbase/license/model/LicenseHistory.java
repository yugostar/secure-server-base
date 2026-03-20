package com.security.serverbase.license.model;

import com.security.serverbase.security.AppUser;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "license_history")
public class LicenseHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "license_id", nullable = false)
    private License license;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private AppUser user;

    @Column(nullable = false, length = 30)
    private String status;

    @Column(name = "change_date", nullable = false)
    private Instant changeDate;

    @Column(length = 500)
    private String description;

    @PrePersist
    public void onCreate() {
        if (changeDate == null) {
            changeDate = Instant.now();
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

    public AppUser getUser() {
        return user;
    }

    public void setUser(AppUser user) {
        this.user = user;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getChangeDate() {
        return changeDate;
    }

    public void setChangeDate(Instant changeDate) {
        this.changeDate = changeDate;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
