package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Intentionally Vulnerable Spring Boot Application
 * DO NOT USE IN PRODUCTION - FOR SECURITY TESTING ONLY
 *
 * This application contains numerous security vulnerabilities
 * for testing automated remediation tools.
 */
@SpringBootApplication
public class VulnerableApplication {

    // VULNERABILITY: Hardcoded secrets (CWE-798)
    public static final String JWT_SECRET = "super_secret_jwt_key_12345";
    public static final String ADMIN_PASSWORD = "admin123";
    public static final String DB_PASSWORD = "password123";
    public static final String API_KEY = "AKIA_FAKE_JAVA_KEY_FOR_TESTING_ONLY";

    public static void main(String[] args) {
        // VULNERABILITY: Debug logging enabled
        System.setProperty("logging.level.root", "DEBUG");
        SpringApplication.run(VulnerableApplication.class, args);
    }

    // VULNERABILITY: Insecure CORS configuration (CWE-942)
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("*")  // Allows any origin
                        .allowedMethods("*")  // Allows all HTTP methods
                        .allowedHeaders("*")  // Allows all headers
                        .allowCredentials(true);  // Dangerous with wildcard origin
            }
        };
    }
}
