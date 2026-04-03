package com.security.serverbase.signature;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

@Service
public class SignatureKeyStoreService {

    private final SignatureProperties properties;
    private final ResourceLoader resourceLoader;

    private volatile PrivateKey privateKey;
    private volatile PublicKey publicKey;

    public SignatureKeyStoreService(SignatureProperties properties, ResourceLoader resourceLoader) {
        this.properties = properties;
        this.resourceLoader = resourceLoader;
    }

    public PrivateKey getPrivateKey() {
        ensureLoaded();
        return privateKey;
    }

    public PublicKey getPublicKey() {
        ensureLoaded();
        return publicKey;
    }

    private void ensureLoaded() {
        if (privateKey != null && publicKey != null) {
            return;
        }
        synchronized (this) {
            if (privateKey != null && publicKey != null) {
                return;
            }
            loadKeys();
        }
    }

    private void loadKeys() {
        validateProperties();
        try {
            KeyStore keyStore = KeyStore.getInstance(properties.getKeyStoreType());
            Resource resource = resourceLoader.getResource(resolvePath(properties.getKeyStorePath()));
            if (!resource.exists()) {
                throw new IllegalStateException("Signature keystore not found: " + properties.getKeyStorePath());
            }

            try (InputStream inputStream = resource.getInputStream()) {
                keyStore.load(inputStream, properties.getKeyStorePassword().toCharArray());
            }

            char[] keyPassword = resolveKeyPassword();
            Key key = keyStore.getKey(properties.getKeyAlias(), keyPassword);
            if (!(key instanceof PrivateKey loadedPrivateKey)) {
                throw new IllegalStateException("Alias '" + properties.getKeyAlias() + "' does not contain a private key");
            }

            Certificate certificate = keyStore.getCertificate(properties.getKeyAlias());
            if (certificate == null) {
                throw new IllegalStateException("Certificate not found for alias '" + properties.getKeyAlias() + "'");
            }

            this.privateKey = loadedPrivateKey;
            this.publicKey = certificate.getPublicKey();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to load signature keys", ex);
        }
    }

    private void validateProperties() {
        if (isBlank(properties.getKeyStorePath()) || isBlank(properties.getKeyStorePassword()) || isBlank(properties.getKeyAlias())) {
            throw new IllegalStateException("Signature keystore configuration is incomplete. Required: signature.key-store-path, signature.key-store-password, signature.key-alias");
        }
    }

    private char[] resolveKeyPassword() {
        String password = isBlank(properties.getKeyPassword())
                ? properties.getKeyStorePassword()
                : properties.getKeyPassword();
        return password.toCharArray();
    }

    private String resolvePath(String path) {
        if (path.startsWith("classpath:") || path.startsWith("file:")) {
            return path;
        }
        return Paths.get(path).toUri().toString();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
