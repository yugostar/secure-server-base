package com.security.serverbase.signature;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SignatureProperties.class)
public class SignatureModuleConfig {
}
