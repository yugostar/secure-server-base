package com.security.serverbase.license.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.serverbase.license.dto.Ticket;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

@Service
public class TicketSignatureService {

    private final ObjectMapper objectMapper;
    private final ResourceLoader resourceLoader;

    @Value("${server.ssl.key-store:}")
    private String keyStorePath;

    @Value("${server.ssl.key-store-password:}")
    private String keyStorePassword;

    @Value("${server.ssl.key-alias:}")
    private String keyAlias;

    private PrivateKey privateKey;

    public TicketSignatureService(ObjectMapper objectMapper, ResourceLoader resourceLoader) {
        this.objectMapper = objectMapper;
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        try {
            if (keyStorePath != null && !keyStorePath.isBlank() && keyStorePassword != null && !keyStorePassword.isBlank() && keyAlias != null && !keyAlias.isBlank()) {
                String resourcePath = keyStorePath;
                if (!keyStorePath.startsWith("file:") && !keyStorePath.startsWith("classpath:")) {
                    resourcePath = java.nio.file.Paths.get(keyStorePath).toUri().toString();
                }
                Resource resource = resourceLoader.getResource(resourcePath);
                if (resource.exists()) {
                    KeyStore keyStore = KeyStore.getInstance("PKCS12");
                    try (InputStream is = resource.getInputStream()) {
                        keyStore.load(is, keyStorePassword.toCharArray());
                    }
                    Key key = keyStore.getKey(keyAlias, keyStorePassword.toCharArray());
                    if (key instanceof PrivateKey pk) {
                        this.privateKey = pk;
                        return;
                    }
                }
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.privateKey = generator.generateKeyPair().getPrivate();
        } catch (Exception ex) {
            throw new IllegalStateException("Не удалось инициализировать подпись тикета", ex);
        }
    }

    public String sign(Ticket ticket) {
        try {
            byte[] payload = objectMapper.writeValueAsString(ticket).getBytes(StandardCharsets.UTF_8);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(payload);
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception ex) {
            throw new IllegalStateException("Не удалось подписать тикет", ex);
        }
    }
}
