package com.security.serverbase.signature;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

@Component
public class JsonCanonicalizer {

    private final ObjectMapper objectMapper;

    public JsonCanonicalizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public byte[] canonicalize(Object payload) {
        try {
            JsonNode tree = objectMapper.valueToTree(payload);
            String canonicalJson = writeNode(tree);
            return canonicalJson.getBytes(StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to canonicalize payload", ex);
        }
    }

    private String writeNode(JsonNode node) {
        if (node == null || node.isNull()) {
            return "null";
        }
        if (node.isObject()) {
            List<Map.Entry<String, JsonNode>> entries = new ArrayList<>();
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            fields.forEachRemaining(entries::add);
            entries.sort(Comparator.comparing(Map.Entry::getKey));

            StringBuilder sb = new StringBuilder();
            sb.append('{');
            for (int i = 0; i < entries.size(); i++) {
                Map.Entry<String, JsonNode> entry = entries.get(i);
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(quote(entry.getKey())).append(':').append(writeNode(entry.getValue()));
            }
            sb.append('}');
            return sb.toString();
        }
        if (node.isArray()) {
            StringBuilder sb = new StringBuilder();
            sb.append('[');
            for (int i = 0; i < node.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(writeNode(node.get(i)));
            }
            sb.append(']');
            return sb.toString();
        }
        if (node.isTextual()) {
            return quote(node.textValue());
        }
        if (node.isNumber()) {
            return node.numberValue().toString();
        }
        if (node.isBoolean()) {
            return Boolean.toString(node.booleanValue());
        }
        throw new IllegalStateException("Unsupported JSON node type for canonicalization: " + node.getNodeType());
    }

    private String quote(String value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to escape JSON string", ex);
        }
    }
}
