package com.security.serverbase.license.model;

import com.security.serverbase.security.AppUser;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "license")
public class License {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 120)
    private String code;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private AppUser user;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "type_id", nullable = false)
    private LicenseType type;

    @Column(name = "first_activation_date")
    private Instant firstActivationDate;

    @Column(name = "ending_date")
    private Instant endingDate;

    @Column(nullable = false)
    private boolean blocked;

    @Column(name = "device_count", nullable = false)
    private Integer deviceCount;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private AppUser owner;

    @Column(length = 500)
    private String description;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public AppUser getUser() {
        return user;
    }

    public void setUser(AppUser user) {
        this.user = user;
    }

    public Product getProduct() {
        return product;
    }

    public void setProduct(Product product) {
        this.product = product;
    }

    public LicenseType getType() {
        return type;
    }

    public void setType(LicenseType type) {
        this.type = type;
    }

    public Instant getFirstActivationDate() {
        return firstActivationDate;
    }

    public void setFirstActivationDate(Instant firstActivationDate) {
        this.firstActivationDate = firstActivationDate;
    }

    public Instant getEndingDate() {
        return endingDate;
    }

    public void setEndingDate(Instant endingDate) {
        this.endingDate = endingDate;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public Integer getDeviceCount() {
        return deviceCount;
    }

    public void setDeviceCount(Integer deviceCount) {
        this.deviceCount = deviceCount;
    }

    public AppUser getOwner() {
        return owner;
    }

    public void setOwner(AppUser owner) {
        this.owner = owner;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
