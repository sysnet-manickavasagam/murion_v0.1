package com.example.murion.v10.Controller;

import com.example.murion.v10.Entity.CiscoAdvisory;
import com.example.murion.v10.Service.ApiService;
import com.example.murion.v10.Entity.VendorFetchLog;
import com.example.murion.v10.Repository.VendorFetchLogRepository;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequestMapping("/api")
public class ApiController {

    private final ApiService apiService;

    public ApiController(ApiService apiService) {
        this.apiService = apiService;
    }

    // Endpoint to fetch and store Cisco advisories
    @GetMapping("/fetch-cisco")
    public String fetchCiscoAdvisories() {
        try {
            apiService.fetchAndStoreCiscoAdvisories();
            return "Cisco advisories fetched and stored successfully.";
        } catch (Exception e) {
            return "Failed to fetch Cisco advisories: " + e.getMessage();
        }
    }

    // Endpoint to fetch NVD (National Vulnerability Database) data for Cisco
    @GetMapping("/fetch-nvd")
    public Map<String, Object> fetchNvdData() {
        try {
            return apiService.fetchNVDData();
        } catch (Exception e) {
            return Map.of("status", "error", "message", e.getMessage());
        }
    }

    // Optional unified endpoint for backward compatibility
    @GetMapping("/fetch")
    public Map<String, Object> fetchAllData() {
        return apiService.fetchNVDData(); // currently calls NVD
    }


    @PostMapping("/checkVersion")
    public ResponseEntity<?> check(
            @RequestParam String vendor,
            @RequestParam String product,
            @RequestParam String version) {

        return ResponseEntity.ok(apiService.checkProductVersion(vendor, product, version));
    }

    @GetMapping("/cisco/search")
    public JsonNode searchCiscoData(@RequestParam String product , String version) throws Exception {
        return apiService.fetchLatestByProduct(product , version);
    }





}