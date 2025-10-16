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
                .pathMatchers(
                    "/actuator/**",
                    "/api/vendors/register-init",
                    "/api/vendors/verify-otp",
                    "/api/vendors/resend-otp",
                    "/api/vendors/login",
                    "/api/vendors/forget-password",
                    "/api/vendors/reset-password",
                    "/api/customers/register-init",
                    "/api/customers/verify-otp",
                    "/api/customers/resend-otp",
                    "/api/customers/login",
                    "/api/customers/forget-password",
                    "/api/customers/reset-password"
                ).permitAll()
                .pathMatchers("/api/vendors/**").hasRole("VENDOR")
                .pathMatchers("/api/cart/**").hasRole( "CUSTOMER")
                .pathMatchers("/api/customers/**").hasRole("CUSTOMER")
                .pathMatchers("/api/orders/**").hasAnyRole("VENDOR", "CUSTOMER")
                .pathMatchers("/api/products/**").permitAll() 
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
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return new CorsWebFilter(source);
    }
}