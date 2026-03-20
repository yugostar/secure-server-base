package com.security.serverbase.license.service;

import com.security.serverbase.license.model.LicenseType;
import com.security.serverbase.license.model.Product;
import com.security.serverbase.license.repository.LicenseTypeRepository;
import com.security.serverbase.license.repository.ProductRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class CatalogBootstrapRunner implements ApplicationRunner {

    private final ProductRepository productRepository;
    private final LicenseTypeRepository licenseTypeRepository;

    public CatalogBootstrapRunner(ProductRepository productRepository, LicenseTypeRepository licenseTypeRepository) {
        this.productRepository = productRepository;
        this.licenseTypeRepository = licenseTypeRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (productRepository.count() == 0) {
            Product product = new Product();
            product.setName("Secure AV");
            product.setBlocked(false);
            productRepository.save(product);
        }
        if (licenseTypeRepository.count() == 0) {
            LicenseType type = new LicenseType();
            type.setName("STANDARD_30");
            type.setDefaultDurationInDays(30);
            type.setDescription("Стандартная лицензия на 30 дней");
            licenseTypeRepository.save(type);
        }
    }
}
