package com.tlcn.api_gateway.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(new KeycloakConvertor());

        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(auth -> auth
                // Public endpoints - no authentication required
                .pathMatchers(
                    "/api/vendors/register-init",
                    "/api/vendors/verify-otp/**",
                    "/api/vendors/resend-otp",
                    "/api/vendors/login",
                    "/api/vendors/forget-password",
                    "/api/vendors/reset-password",
                    "/api/customers/register-init",
                    "/api/customers/verify-otp/**",
                    "/api/customers/resend-otp",
                    "/api/customers/login",
                    "/api/customers/forget-password",
                    "/api/customers/reset-password",
                    "/actuator/**"
                ).permitAll()
                
                // Protected endpoints - both roles allowed
                .pathMatchers("/api/vendors/**").hasAnyRole("VENDOR","ADMIN")
                
                // Customer only endpoints
                .pathMatchers("/api/cart/**").hasRole("CUSTOMER")
                .pathMatchers("/customers/**").hasRole("CUSTOMER")
                
                // Protected endpoints - both roles allowed
                .pathMatchers("/api/orders/**").hasAnyRole("VENDOR", "CUSTOMER")
                
                // Public products endpoint
                .pathMatchers("/api/products/**").permitAll()
                
                // Public flash-sales and discounts
                .pathMatchers("/api/flash-sales/**", "/api/discounts/**").permitAll()
                
                // All other requests must be authenticated
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> 
                oauth2.jwt(jwtSpec -> 
                    jwtSpec.jwtAuthenticationConverter(
                        new ReactiveJwtAuthenticationConverterAdapter(jwtConverter)
                    )
                )
            )
            .build();
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization", "X-Requested-With"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "X-Total-Count", "X-Page-Number"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return new CorsWebFilter(source);
    }
}
