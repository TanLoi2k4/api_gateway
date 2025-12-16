package com.tlcn.api_gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@Component
public class LoggingGatewayFilter implements GlobalFilter, Ordered {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        long startTime = System.currentTimeMillis();
        
        String requestId = exchange.getRequest().getId();
        String method = exchange.getRequest().getMethod() != null 
            ? exchange.getRequest().getMethod().toString() 
            : "UNKNOWN";
        String path = exchange.getRequest().getPath().value();
        String remoteAddress = exchange.getRequest().getRemoteAddress() != null 
            ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress() 
            : "Unknown";
        
        // Log incoming request
        log.info("=== INCOMING REQUEST ===");
        log.info("Request ID: {}", requestId);
        log.info("Timestamp: {}", LocalDateTime.now().format(FORMATTER));
        log.info("Method: {} | Path: {}", method, path);
        log.info("Remote Address: {}", remoteAddress);
        log.info("User-Agent: {}", exchange.getRequest().getHeaders().getFirst("User-Agent"));
        
        // Get Authorization header (without token value for security)
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && !authHeader.isEmpty()) {
            log.info("Authentication: Present");
        }
        
        return chain.filter(exchange).doFinally(signal -> {
            long duration = System.currentTimeMillis() - startTime;
            int statusCode = exchange.getResponse().getStatusCode() != null 
                ? exchange.getResponse().getStatusCode().value() 
                : 0;
            
            // Log response
            log.info("=== OUTGOING RESPONSE ===");
            log.info("Request ID: {}", requestId);
            log.info("Status Code: {}", statusCode);
            log.info("Response Time: {}ms", duration);
            log.info("=============================");
        });
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
