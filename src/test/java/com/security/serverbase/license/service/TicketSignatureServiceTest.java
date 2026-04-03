package com.security.serverbase.license.service;

import com.security.serverbase.license.dto.Ticket;
import com.security.serverbase.signature.JsonCanonicalizer;
import com.security.serverbase.signature.SignatureKeyStoreService;
import com.security.serverbase.signature.SignatureProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@TestPropertySource(properties = {
        "signature.key-store-path=file:secure-server-keystore.p12",
        "signature.key-store-type=PKCS12",
        "signature.key-store-password=changeit",
        "signature.key-alias=secure-server",
        "signature.key-password=changeit",
        "signature.algorithm=SHA256withRSA"
})
class TicketSignatureServiceTest {

    @Autowired
    private TicketSignatureService ticketSignatureService;
    @Autowired
    private JsonCanonicalizer jsonCanonicalizer;
    @Autowired
    private SignatureKeyStoreService keyStoreService;
    @Autowired
    private SignatureProperties signatureProperties;

    @Test
    void shouldSignAndVerifyTicket() throws Exception {
        Ticket ticket = new Ticket(
                Instant.parse("2026-04-03T10:15:30Z"),
                300,
                Instant.parse("2026-04-03T10:00:00Z"),
                Instant.parse("2026-05-03T10:00:00Z"),
                UUID.fromString("11111111-1111-1111-1111-111111111111"),
                UUID.fromString("22222222-2222-2222-2222-222222222222"),
                false
        );

        String base64Signature = ticketSignatureService.sign(ticket);

        Signature verifier = Signature.getInstance(signatureProperties.getAlgorithm());
        verifier.initVerify(keyStoreService.getPublicKey());
        verifier.update(jsonCanonicalizer.canonicalize(ticket));

        assertTrue(verifier.verify(Base64.getDecoder().decode(base64Signature)));
    }
}
