package com.example.murion.v10.Controller;

import com.example.murion.v10.Service.ApiService;
import com.example.murion.v10.Entity.VendorFetchLog;
import com.example.murion.v10.Repository.VendorFetchLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final ApiService apiService;

    @Autowired
    private VendorFetchLogRepository logRepository;

    public ApiController(ApiService apiService) {
        this.apiService = apiService;
    }

    // === Quick Fetch Endpoints (Render-compatible) ===

    @GetMapping("/fetch/quick")
    public Map<String, Object> quickFetch(@RequestParam(defaultValue = "5") int pages) {
        return apiService.quickFetch(pages);
    }

    @GetMapping("/fetch/cisco")
    public ResponseEntity<Map<String, Object>> fetchCiscoData() {
        try {
            Map<String, Object> result = apiService.quickFetchAndStoreCiscoAdvisories(5);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                "status", "error", 
                "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/fetch/cisco-fallback")
    public ResponseEntity<Map<String, Object>> fetchCiscoDataFromNVD() {
        try {
            apiService.fetchCiscoDataFromNVD();
            return ResponseEntity.ok(Map.of(
                "status", "success", 
                "message", "Cisco data fetch from NVD triggered successfully"
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                "status", "error", 
                "message", e.getMessage()
            ));
        }
    }

    // === Async Endpoints (for complete fetch) ===

    @GetMapping("/fetch/all")
    public Map<String, Object> fetchAllData() {
        return apiService.fetchAllData();
    }

    @GetMapping("/fetch/async")
    public CompletableFuture<Map<String, Object>> fetchAllDataAsync() {
        return apiService.fetchAllDataAsync();
    }

    // === Status Endpoints ===

    @GetMapping("/fetch/status")
    public Map<String, Object> getFetchStatus() {
        return apiService.getFetchStatus();
    }

    // === Diagnostic Endpoints ===

    @GetMapping("/test/cisco-auth")
    public Map<String, Object> testCiscoAuth() {
        return apiService.testCiscoCredentials();
    }

    // === Stats Endpoints ===

    @GetMapping("/stats/database")
    public Map<String, Object> getDatabaseStats() {
        return apiService.getDatabaseStats();
    }

    // === Log Endpoints ===

    @GetMapping("/logs")
    public ResponseEntity<List<VendorFetchLog>> getAllLogs() {
        return ResponseEntity.ok(logRepository.findAll());
    }

    @GetMapping("/logs/{vendor}")
    public ResponseEntity<VendorFetchLog> getVendorLog(@PathVariable String vendor) {
        return logRepository.findByVendorName(vendor)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // === Backward Compatibility ===

    @GetMapping("/fetch")
    public Map<String, Object> getData() {
        return apiService.fetchNVDData();
    }

    // === Health Check ===

    @GetMapping("/health")
    public Map<String, Object> healthCheck() {
        return Map.of(
            "status", "healthy",
            "timestamp", new java.util.Date().toString(),
            "service", "Murion Security API",
            "version", "1.0"
        );
    }
}
