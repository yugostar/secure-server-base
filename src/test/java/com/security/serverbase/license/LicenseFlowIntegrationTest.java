package com.security.serverbase.license;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.serverbase.license.model.License;
import com.security.serverbase.license.repository.LicenseRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "APP_ADMIN_USERNAME=admin",
        "APP_ADMIN_PASSWORD=Admin123!",
        "APP_JWT_SECRET=1234567890qwertyuiopasdfghjklzxcvbnm"
}, locations = "classpath:application-signature-test.properties")
class LicenseFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private LicenseRepository licenseRepository;

    @Test
    void fullLicenseFlowWorks() throws Exception {
        String adminToken = login("admin", "Admin123!");

        MvcResult register = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "user1",
                                  "password": "User12345!"
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn();
        JsonNode regJson = objectMapper.readTree(register.getResponse().getContentAsString());
        String ownerId = regJson.get("id").asText();

        String userToken = login("user1", "User12345!");

        MvcResult productResult = mockMvc.perform(get("/api/admin/catalog/products")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode products = objectMapper.readTree(productResult.getResponse().getContentAsString());
        String productId = products.get(0).get("id").asText();

        MvcResult typeResult = mockMvc.perform(get("/api/admin/catalog/license-types")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode types = objectMapper.readTree(typeResult.getResponse().getContentAsString());
        String typeId = types.get(0).get("id").asText();

        MvcResult createResult = mockMvc.perform(post("/api/licenses")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "productId": "%s",
                                  "typeId": "%s",
                                  "ownerId": "%s",
                                  "deviceCount": 2,
                                  "blocked": false,
                                  "description": "lab2 license"
                                }
                                """.formatted(productId, typeId, ownerId)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").exists())
                .andReturn();

        JsonNode created = objectMapper.readTree(createResult.getResponse().getContentAsString());
        String activationKey = created.get("code").asText();

        mockMvc.perform(post("/api/licenses/activate")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "activationKey": "%s",
                                  "deviceMac": "AA-BB-CC-DD-EE-01",
                                  "deviceName": "Laptop"
                                }
                                """.formatted(activationKey)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket.userId").value(ownerId))
                .andExpect(jsonPath("$.signature").exists());

        mockMvc.perform(post("/api/licenses/check")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "deviceMac": "AA-BB-CC-DD-EE-01",
                                  "productId": "%s"
                                }
                                """.formatted(productId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket.blocked").value(false))
                .andExpect(jsonPath("$.signature").exists());

        License license = licenseRepository.findByCode(activationKey).orElseThrow();
        license.setEndingDate(Instant.now().plus(1, ChronoUnit.DAYS));
        licenseRepository.save(license);

        mockMvc.perform(post("/api/licenses/renew")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "activationKey": "%s"
                                }
                                """.formatted(activationKey)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signature").exists());
    }

    private String login(String username, String password) throws Exception {
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "%s"
                                }
                                """.formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = objectMapper.readTree(loginResult.getResponse().getContentAsString());
        return json.get("accessToken").asText();
    }
}
