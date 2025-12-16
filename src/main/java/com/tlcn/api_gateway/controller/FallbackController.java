package com.tlcn.api_gateway.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/fallback")
public class FallbackController {

    /**
     * Generic fallback endpoint khi service không available
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> fallback() {
        log.warn("Circuit breaker activated - Service temporarily unavailable");
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "SERVICE_UNAVAILABLE");
        response.put("message", "Service is temporarily unavailable. Please try again later.");
        response.put("timestamp", LocalDateTime.now());
        response.put("errorCode", "CB_OPEN");
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    @GetMapping("/vendor-service")
    public ResponseEntity<Map<String, Object>> vendorServiceFallback() {
        return createFallbackResponse("Vendor Service");
    }

    @GetMapping("/product-service")
    public ResponseEntity<Map<String, Object>> productServiceFallback() {
        return createFallbackResponse("Product Service");
    }

    @GetMapping("/customer-service")
    public ResponseEntity<Map<String, Object>> customerServiceFallback() {
        return createFallbackResponse("Customer Service");
    }

    @GetMapping("/order-service")
    public ResponseEntity<Map<String, Object>> orderServiceFallback() {
        return createFallbackResponse("Order Service");
    }

    @GetMapping("/cart-service")
    public ResponseEntity<Map<String, Object>> cartServiceFallback() {
        return createFallbackResponse("Cart Service");
    }

    @GetMapping("/paypromo-service")
    public ResponseEntity<Map<String, Object>> paypromoServiceFallback() {
        return createFallbackResponse("PayPromo Service");
    }

    private ResponseEntity<Map<String, Object>> createFallbackResponse(String serviceName) {
        log.warn("Circuit breaker activated for: {}", serviceName);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "SERVICE_UNAVAILABLE");
        response.put("message", serviceName + " is temporarily unavailable. Please try again later.");
        response.put("service", serviceName);
        response.put("timestamp", LocalDateTime.now());
        response.put("errorCode", "CB_OPEN");
        response.put("suggestion", "Please retry your request in a few moments");
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }
}
