package com.security.serverbase.license.service;

import com.security.serverbase.license.model.Product;
import com.security.serverbase.license.repository.ProductRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class ProductService {

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public Product getProductOrFail(UUID id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Продукт не найден"));
        if (product.isBlocked()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Продукт заблокирован");
        }
        return product;
    }
}
