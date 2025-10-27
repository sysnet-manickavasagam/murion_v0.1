package com.example.murion.v10.Controller;

import com.example.murion.v10.Service.ApiService;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import com.example.murion.v10.Entity.VendorFetchLog;
import com.example.murion.v10.Repository.VendorFetchLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import java.util.List;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final ApiService apiService;

    public ApiController(ApiService apiService) {
        this.apiService = apiService;
    }
    
    @Autowired
    private VendorFetchLogRepository logRepository;

    // Endpoint for Cisco security advisories only
    @GetMapping("/fetch/cisco")
    public ResponseEntity<Map<String, Object>> fetchCiscoData() {
        try {
            apiService.fetchAndStoreCiscoAdvisories();
            return ResponseEntity.ok(Map.of("status", "success", "message", "Cisco advisories fetch triggered successfully"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("status", "error", "message", e.getMessage()));
        }
    }

    // Endpoint for NVD data only
    @GetMapping("/nvd/cisco")
    public Map<String, Object> getNVDData() {
        return apiService.fetchNVDData();
    }
    
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

    // Original endpoint for backward compatibility (points to NVD)
    @GetMapping("/fetch")
    public Map<String, Object> getData() {
        return apiService.fetchNVDData();
    }
}
