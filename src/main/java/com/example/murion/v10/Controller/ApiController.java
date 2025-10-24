package com.example.murion.v10.Controller;

import com.example.murion.v10.Service.ApiService;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final ApiService apiService;

    public ApiController(ApiService apiService) {
        this.apiService = apiService;
    }

    // Endpoint for Cisco security advisories only
    @GetMapping("/fetch-cisco")
    public String fetchCiscoAdvisories() {
        try {
            apiService.fetchAndStoreCiscoAdvisories();
            return "Cisco advisories fetched and stored successfully.";
        } catch (Exception e) {
            return "Failed: " + e.getMessage();
        }
    }


    // Endpoint for NVD data only
    @GetMapping("/nvd/cisco")
    public Map<String, Object> getNVDData() {
        return apiService.fetchNVDData();
    }

    // Original endpoint for backward compatibility (points to NVD)
    @GetMapping("/fetch")
    public Map<String, Object> getData() {
        return apiService.fetchNVDData();
    }
}