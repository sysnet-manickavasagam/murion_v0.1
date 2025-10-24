//package com.example.murion.v10.Controller;
//
//import com.example.murion.v10.Service.CiscoApiService;
//import com.example.murion.v10.Service.TokenService;
//import org.springframework.web.bind.annotation.*;
//import java.util.Map;
//
//@RestController
//@RequestMapping("/api/cisco")
//public class CiscoController {
//
//    private final CiscoApiService ciscoApiService;
//
//    public CiscoController(CiscoApiService ciscoApiService) {
//        this.ciscoApiService = ciscoApiService;
//    }
//
//    // Test token connection
//    @GetMapping("/test-token")
//    public Map<String, Object> testToken() {
//        return ciscoApiService.testToken();
//    }
//
//    // Get token status
//    @GetMapping("/token-status")
//    public Map<String, Object> getTokenStatus() {
//        return ciscoApiService.getTokenStatus();
//    }
//
//    // Fetch Cisco advisories and store in database
//    @GetMapping("/fetch-store")
//    public Map<String, Object> fetchAndStoreAdvisories() {
//        return ciscoApiService.fetchAndStoreCiscoAdvisories();
//    }
//
//    // Get version fixes for a specific CVE
//    @GetMapping("/version-fixes/{cveId}")
//    public Map<String, Object> getVersionFixes(@PathVariable String cveId) {
//        return ciscoApiService.getVersionFixes(cveId);
//    }
//
//    // Get statistics about stored vulnerabilities
//    @GetMapping("/stats")
//    public Map<String, Object> getVulnerabilityStats() {
//        return ciscoApiService.getVulnerabilityStats();
//    }
//
//    // Health check endpoint
//    @GetMapping("/health")
//    public Map<String, Object> healthCheck() {
//        return Map.of(
//                "status", "healthy",
//                "service", "Cisco API Service",
//                "timestamp", java.time.LocalDateTime.now().toString()
//        );
//    }
//}