package com.security.serverbase.license.service;

import com.security.serverbase.license.dto.Ticket;
import com.security.serverbase.signature.JsonCanonicalizer;
import com.security.serverbase.signature.SignatureKeyStoreService;
import com.security.serverbase.signature.SignatureProperties;
import org.springframework.stereotype.Service;

import java.security.Signature;
import java.util.Base64;

@Service
public class TicketSignatureService {

    private final JsonCanonicalizer jsonCanonicalizer;
    private final SignatureKeyStoreService keyStoreService;
    private final SignatureProperties signatureProperties;

    public TicketSignatureService(JsonCanonicalizer jsonCanonicalizer,
                                  SignatureKeyStoreService keyStoreService,
                                  SignatureProperties signatureProperties) {
        this.jsonCanonicalizer = jsonCanonicalizer;
        this.keyStoreService = keyStoreService;
        this.signatureProperties = signatureProperties;
    }

    public String sign(Ticket ticket) {
        try {
            byte[] payload = jsonCanonicalizer.canonicalize(ticket);
            Signature signature = Signature.getInstance(signatureProperties.getAlgorithm());
            signature.initSign(keyStoreService.getPrivateKey());
            signature.update(payload);
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception ex) {
            throw new IllegalStateException("Не удалось подписать тикет", ex);
        }
    }
}
