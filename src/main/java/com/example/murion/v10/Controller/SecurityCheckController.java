package com.example.murion.v10.Controller;

import com.example.murion.v10.Entity.CiscoAdvisory;
import com.example.murion.v10.Repository.CiscoAdvisoryRepository;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/security")
public class SecurityCheckController {

    @Autowired
    private CiscoAdvisoryRepository advisoryRepository;

    @PostMapping("/check")
    public Map<String, Object> checkVersionStatus(
            @RequestParam String deviceName,
            @RequestParam String vendorName,
            @RequestParam String productName,
            @RequestParam String productVersion
    ) {

        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> affectedList = new ArrayList<>();

        // Get all CVE records
        List<CiscoAdvisory> records = advisoryRepository.findAll();
        boolean vulnerable = false;

        for (CiscoAdvisory advisory : records) {

            JsonNode csaf = advisory.getCsaf();
            if (csaf == null || csaf.isEmpty()) continue;

            JsonNode productTree = csaf.path("product_tree");

            if (!productTree.isObject()) continue;

            JsonNode fullProducts = productTree.path("full_product_names");

            if (!fullProducts.isArray()) continue;

            for (JsonNode prod : fullProducts) {

                String pName = prod.path("name").asText("");
                if (!pName.toLowerCase().contains(productName.toLowerCase())) {
                    continue;   // product not matching
                }

                // Extract version ranges
                JsonNode productVersions = prod.path("product_version");
                List<String> fixedVersions = new ArrayList<>();

                boolean thisVersionVulnerable = false;

                if (productVersions.isArray()) {
                    for (JsonNode ver : productVersions) {
                        String status = ver.path("status").asText("");
                        String version = ver.path("version").asText("");

                        if (status.equalsIgnoreCase("affected")) {
                            if (version.equalsIgnoreCase(productVersion)) {
                                thisVersionVulnerable = true;
                            }
                        }
                        if (status.equalsIgnoreCase("fixed")) {
                            fixedVersions.add(version);
                        }
                    }
                }

                if (thisVersionVulnerable) {
                    vulnerable = true;

                    Map<String, Object> affected = new LinkedHashMap<>();
                    affected.put("cveId", advisory.getCveId());
                    affected.put("product", productName);
                    affected.put("currentVersion", productVersion);
                    affected.put("fixedVersions", fixedVersions);

                    affectedList.add(affected);
                }
            }
        }

        result.put("deviceName", deviceName);
        result.put("vendorName", vendorName);
        result.put("productName", productName);
        result.put("productVersion", productVersion);
        result.put("isSecure", !vulnerable);
        result.put("affectedData", affectedList);

        if (!vulnerable) {
            result.put("message", "Version is secure ✅");
        } else {
            result.put("message", "Version is vulnerable ❌");
        }

        return result;
    }
                }
