package com.tlcn.api_gateway.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class KeycloakConvertor implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakConvertor.class);

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        if (source.getClaims() == null) {
            logger.warn("JWT claims are null");
            return new ArrayList<>();
        }
        Map<String, Object> realmAccess = (Map<String, Object>) source.getClaims().get("realm_access");
        if (realmAccess == null || realmAccess.isEmpty()) {
            logger.debug("No realm_access found in JWT claims");
            return new ArrayList<>();
        }
        List<String> roles = (List<String>) realmAccess.get("roles");
        if (roles == null) {
            logger.debug("No roles found in realm_access");
            return new ArrayList<>();
        }
        logger.info("Converted roles: {}", roles);
        return roles.stream()
            .map(roleName -> new SimpleGrantedAuthority("ROLE_" + roleName))
            .collect(Collectors.toList());
    }
}