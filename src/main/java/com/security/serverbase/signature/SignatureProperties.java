package com.security.serverbase.signature;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "signature")
public class SignatureProperties {
    private String keyStorePath;
    private String keyStoreType = "PKCS12";
    private String keyStorePassword;
    private String keyAlias;
    private String keyPassword;
    private String algorithm = "SHA256withRSA";

    public String getKeyStorePath() { return keyStorePath; }
    public void setKeyStorePath(String keyStorePath) { this.keyStorePath = keyStorePath; }
    public String getKeyStoreType() { return keyStoreType; }
    public void setKeyStoreType(String keyStoreType) { this.keyStoreType = keyStoreType; }
    public String getKeyStorePassword() { return keyStorePassword; }
    public void setKeyStorePassword(String keyStorePassword) { this.keyStorePassword = keyStorePassword; }
    public String getKeyAlias() { return keyAlias; }
    public void setKeyAlias(String keyAlias) { this.keyAlias = keyAlias; }
    public String getKeyPassword() { return keyPassword; }
    public void setKeyPassword(String keyPassword) { this.keyPassword = keyPassword; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
}
