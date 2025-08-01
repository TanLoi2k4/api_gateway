package com.tlcn.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .pathMatchers("/actuator/**").permitAll() 
                .pathMatchers("/api/vendors/**").hasAnyRole("VENDOR", "ADMIN") 
                .pathMatchers("/api/customers/**").hasAnyRole("CUSTOMER", "ADMIN") 
                .pathMatchers("/api/orders/**").hasAnyRole("VENDOR", "CUSTOMER", "ADMIN") 
                .pathMatchers("/api/products/**").permitAll() 
                .anyExchange().authenticated() 
            .and()
            .oauth2ResourceServer()
                .jwt(); 
        return http.build();
    }
}