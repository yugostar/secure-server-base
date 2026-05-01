package com.security.serverbase.signature;

import org.springframework.stereotype.Service;

import java.security.Signature;

@Service
public class RawSignatureService {

    private final SignatureKeyStoreService keyStoreService;
    private final SignatureProperties signatureProperties;

    public RawSignatureService(SignatureKeyStoreService keyStoreService,
                               SignatureProperties signatureProperties) {
        this.keyStoreService = keyStoreService;
        this.signatureProperties = signatureProperties;
    }

    public byte[] signBytes(byte[] payload) {
        try {
            Signature signature = Signature.getInstance(signatureProperties.getAlgorithm());
            signature.initSign(keyStoreService.getPrivateKey());
            signature.update(payload);
            return signature.sign();
        } catch (Exception ex) {
            throw new IllegalStateException("Не удалось подписать бинарные данные", ex);
        }
    }
}
