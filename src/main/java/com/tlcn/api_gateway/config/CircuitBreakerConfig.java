package com.tlcn.api_gateway.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

@Slf4j
@Configuration
public class CircuitBreakerConfig {

    private final CircuitBreakerRegistry circuitBreakerRegistry;

    public CircuitBreakerConfig(CircuitBreakerRegistry circuitBreakerRegistry) {
        this.circuitBreakerRegistry = circuitBreakerRegistry;
    }

    /**
     * Setup event listeners cho CircuitBreaker khi application start
     */
    @EventListener(ContextRefreshedEvent.class)
    public void setupCircuitBreakerListeners() {
        log.info("Setting up CircuitBreaker event listeners...");
        circuitBreakerRegistry.getAllCircuitBreakers()
            .forEach(this::attachListeners);
    }

    private void attachListeners(CircuitBreaker circuitBreaker) {
        String cbName = circuitBreaker.getName();

        // Log state transitions
        circuitBreaker.getEventPublisher()
            .onStateTransition(event -> {
                String state = event.getStateTransition().getToState().toString();
                switch (state) {
                    case "OPEN" -> 
                        log.error("🔴 CircuitBreaker '{}' is OPEN - Service unavailable", cbName);
                    case "HALF_OPEN" -> 
                        log.warn("🟡 CircuitBreaker '{}' is HALF_OPEN - Testing recovery...", cbName);
                    case "CLOSED" -> 
                        log.info("🟢 CircuitBreaker '{}' is CLOSED - Service recovered", cbName);
                }
            })
            // Log errors and successes
            .onError(event -> 
                log.debug("CircuitBreaker '{}' - Error: {}", cbName, event.getThrowable().getMessage()))
            .onSuccess(event -> 
                log.trace("CircuitBreaker '{}' - Request succeeded", cbName));

        log.debug("CircuitBreaker '{}' listeners attached", cbName);
    }
}
