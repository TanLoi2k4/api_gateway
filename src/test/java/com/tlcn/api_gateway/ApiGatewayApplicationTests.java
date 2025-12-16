package com.tlcn.api_gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource; // Import class này

@SpringBootTest
// Ghi đè cấu hình gateway để loại bỏ RequestRateLimiter khi chạy test
@TestPropertySource(properties = {
    "spring.cloud.gateway.routes[0].id=test-route",
    "spring.cloud.gateway.routes[0].uri=lb://test-service",
    "spring.cloud.gateway.routes[0].predicates[0]=Path=/api/test/**",
    "spring.cloud.gateway.routes[0].filters[0]=StripPrefix=2" // Chỉ giữ lại 1 filter cơ bản
})
class ApiGatewayApplicationTests {

    @Test
    void contextLoads() {
        // Test này chỉ kiểm tra ApplicationContext có load thành công không
    }
}