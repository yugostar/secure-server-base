package com.security.serverbase.signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class JsonCanonicalizer {

    private final ObjectMapper objectMapper;

    public JsonCanonicalizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public byte[] canonicalize(Object payload) {
        try {
            String json = objectMapper.writeValueAsString(payload);
            String canonicalJson = new org.erdtman.jcs.JsonCanonicalizer(json).getEncodedString();
            return canonicalJson.getBytes(StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalStateException("Не удалось канонизировать", ex);
        }
    }
}
