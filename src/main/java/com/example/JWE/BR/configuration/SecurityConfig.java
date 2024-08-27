package com.example.JWE.BR.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable() // Desactiva CSRF si no es necesario
            .authorizeRequests()
            .requestMatchers("/api/jwe/encrypt").permitAll() // Permite acceso sin autenticación a /api/jwe/encrypt
            .anyRequest().authenticated(); // Requiere autenticación para otros endpoints
        return http.build();
    }
}

