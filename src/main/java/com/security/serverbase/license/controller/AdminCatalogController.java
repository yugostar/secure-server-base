package com.security.serverbase.license.controller;

import com.security.serverbase.license.model.LicenseType;
import com.security.serverbase.license.model.Product;
import com.security.serverbase.license.repository.LicenseTypeRepository;
import com.security.serverbase.license.repository.ProductRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin/catalog")
public class AdminCatalogController {

    private final ProductRepository productRepository;
    private final LicenseTypeRepository licenseTypeRepository;

    public AdminCatalogController(ProductRepository productRepository, LicenseTypeRepository licenseTypeRepository) {
        this.productRepository = productRepository;
        this.licenseTypeRepository = licenseTypeRepository;
    }

    @GetMapping("/products")
    public List<Product> products() {
        return productRepository.findAll();
    }

    @GetMapping("/license-types")
    public List<LicenseType> licenseTypes() {
        return licenseTypeRepository.findAll();
    }
}
