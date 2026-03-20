package com.security.serverbase.license.repository;

import com.security.serverbase.license.model.License;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface LicenseRepository extends JpaRepository<License, UUID> {
    Optional<License> findByCode(String code);

    @Query("""
            select l from License l
            join DeviceLicense dl on dl.license = l
            where dl.device.id = :deviceId
              and l.user.id = :userId
              and l.product.id = :productId
              and l.blocked = false
              and (l.endingDate is null or l.endingDate >= :now)
            order by l.endingDate desc
            """)
    Optional<License> findActiveByDeviceUserAndProduct(@Param("deviceId") UUID deviceId,
                                                       @Param("userId") UUID userId,
                                                       @Param("productId") UUID productId,
                                                       @Param("now") Instant now);
}
