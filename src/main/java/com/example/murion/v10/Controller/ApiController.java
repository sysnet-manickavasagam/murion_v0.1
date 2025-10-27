package com.example.murion.v10.Controller;

import com.example.murion.v10.Service.ApiService;
import com.example.murion.v10.Entity.VendorFetchLog;
import com.example.murion.v10.Repository.VendorFetchLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final ApiService apiService;

    @Autowired
    private VendorFetchLogRepository logRepository;

    public ApiController(ApiService apiService) {
        this.apiService = apiService;
    }

    // === Cisco API Endpoints ===

    @GetMapping("/fetch/cisco")
    public ResponseEntity<Map<String, Object>> fetchCiscoData() {
        try {
            apiService.fetchAndStoreCiscoAdvisories();
            return ResponseEntity.ok(Map.of(
                "status", "success", 
                "message", "Cisco advisories fetch triggered successfully"
            ));
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
                "message", "Cisco data fetch from NVD fallback triggered successfully"
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                "status", "error", 
                "message", e.getMessage()
            ));
        }
    }

    // === Diagnostic Endpoints ===

    @GetMapping("/diagnose/cisco-auth")
    public Map<String, Object> diagnoseCiscoAuth() {
        return apiService.diagnoseCiscoAuth();
    }

    @GetMapping("/test/cisco-auth")
    public Map<String, Object> testCiscoAuth() {
        return apiService.testCiscoCredentials();
    }

    @GetMapping("/cisco-registration-help")
    public Map<String, Object> getRegistrationHelp() {
        return apiService.getRegistrationInstructions();
    }

    // === NVD API Endpoints ===

    @GetMapping("/nvd/cisco")
    public Map<String, Object> getNVDData() {
        return apiService.fetchNVDData();
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
