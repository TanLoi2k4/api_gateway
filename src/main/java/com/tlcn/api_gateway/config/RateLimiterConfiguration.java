package com.tlcn.api_gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
public class RateLimiterConfiguration {

    /**
     * Xác định key cho rate limiting dựa trên user từ JWT token (PRIMARY)
     * Nếu không có user, dùng "anonymous"
     */
    @Bean
    @Primary
    public KeyResolver userKeyResolver() {
        return exchange -> exchange.getPrincipal()
            .map(p -> {
                String userId = p.getName();
                log.debug("Rate limit key for user: {}", userId);
                return userId;
            })
            .onErrorResume(e -> {
                log.debug("No principal found, using anonymous for rate limit");
                return Mono.just("anonymous");
            })
            .defaultIfEmpty("anonymous");
    }

    /**
     * Alternative: Dùng IP address thay vì user
     */
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            ServerHttpRequest request = exchange.getRequest();
            String clientIp = request.getHeaders().getFirst("X-Forwarded-For");
            
            if (clientIp == null || clientIp.isEmpty()) {
                clientIp = request.getRemoteAddress() != null 
                    ? request.getRemoteAddress().getAddress().getHostAddress() 
                    : "unknown";
            }
            
            log.debug("Rate limit key for IP: {}", clientIp);
            return Mono.just(clientIp);
        };
    }
}
