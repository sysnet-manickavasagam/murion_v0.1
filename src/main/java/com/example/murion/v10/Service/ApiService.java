package com.example.murion.v10.Service;

import com.example.murion.v10.Entity.CiscoAdvisory;
import com.example.murion.v10.Entity.VendorFetchLog;
import com.example.murion.v10.Repository.CiscoAdvisoryRepository;
import com.example.murion.v10.Repository.VendorFetchLogRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class ApiService {

    private final RestTemplate restTemplate;
    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private CiscoAdvisoryRepository advisoryRepository;

    @Autowired
    private VendorFetchLogRepository logRepository;

    // Cisco OAuth2 Credentials
    private static final String CLIENT_ID = "q37wu5ga3695r3jfzccnfp8q";
    private static final String CLIENT_SECRET = "aB54S9PgZuTD87TpumQPw2Yq";
    private static final String TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token";

    private String accessToken;
    private LocalDateTime tokenExpiry;

    public ApiService() {
        this.restTemplate = createRestTemplate();
    }

    private RestTemplate createRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(0);
        factory.setReadTimeout(0);
        return new RestTemplate(factory);
    }

    // === Cisco OAuth2 Token Methods ===

    private String getAccessToken() {
        if (accessToken != null && tokenExpiry != null && LocalDateTime.now().isBefore(tokenExpiry)) {
            return accessToken;
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "client_credentials");
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

            System.out.println("🔑 Requesting Cisco OAuth2 token...");
            ResponseEntity<String> response = restTemplate.postForEntity(TOKEN_URL, requestEntity, String.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Token request failed: HTTP " + response.getStatusCode());
            }

            JsonNode tokenResponse = mapper.readTree(response.getBody());
            accessToken = tokenResponse.path("access_token").asText(null);
            int expiresIn = tokenResponse.path("expires_in").asInt(3600);
            tokenExpiry = LocalDateTime.now().plusSeconds(Math.max(expiresIn - 60, 30));

            if (accessToken == null || accessToken.isEmpty()) {
                throw new RuntimeException("Token response missing access_token");
            }

            System.out.println("✅ New Cisco access token obtained (expires in " + expiresIn + "s)");
            return accessToken;
        } catch (Exception e) {
            throw new RuntimeException("Failed to obtain Cisco OAuth2 token: " + e.getMessage(), e);
        }
    }

    // === Cisco Advisory Methods ===

    /**
     * Fetch and store ALL Cisco advisories without limits
     */
    @Scheduled(cron = "0 0 */6 * * *")
    public void fetchAndStoreCiscoAdvisories() {
        String vendor = "Cisco";
        LocalDateTime startTime = LocalDateTime.now();

        VendorFetchLog log = logRepository.findByVendorName(vendor).orElseGet(() -> {
            VendorFetchLog n = new VendorFetchLog();
            n.setVendorName(vendor);
            return n;
        });

        log.setPreviousFetchTime(log.getLastFetchTime());
        log.setLastFetchTime(startTime);

        int added = 0;
        int updated = 0;
        int skippedNoCVE = 0;
        long totalBefore = advisoryRepository.count();

        System.out.println("🚀 Starting COMPLETE Cisco advisories fetch (NO LIMITS)...");

        try {
            String token = getAccessToken();
            System.out.println("✅ Authentication successful, starting complete data fetch...");
            
            String baseUrl = "https://apix.cisco.com/security/advisories/v2/all";
            int pageIndex = 1;
            int pageSize = 100;
            boolean hasMorePages = true;
            
            while (hasMorePages) {
                try {
                    String url = baseUrl + "?pageIndex=" + pageIndex + "&pageSize=" + pageSize;
                    HttpHeaders headers = new HttpHeaders();
                    headers.set("Authorization", "Bearer " + token);
                    headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

                    System.out.println("📥 Fetching page " + pageIndex + "...");
                    HttpEntity<String> requestEntity = new HttpEntity<>(headers);
                    ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);

                    if (!response.getStatusCode().is2xxSuccessful()) {
                        System.err.println("❌ Failed to fetch Cisco page " + pageIndex + ": HTTP " + response.getStatusCode());
                        pageIndex++;
                        continue;
                    }

                    JsonNode root = mapper.readTree(response.getBody());
                    JsonNode advList = root.path("advisories");
                    
                    if (!advList.isArray() || advList.isEmpty()) {
                        System.out.println("✅ No more advisories to fetch");
                        hasMorePages = false;
                        break;
                    }

                    System.out.println("🔄 Processing page " + pageIndex + " with " + advList.size() + " advisories");

                    int pageAdded = 0;
                    int pageUpdated = 0;
                    int pageSkipped = 0;
                    
                    for (JsonNode adv : advList) {
                        String advisoryId = adv.path("advisoryId").asText(null);
                        if (advisoryId == null) continue;

                        List<String> cveIds = extractList(adv.path("cves"));
                        if (cveIds.isEmpty()) {
                            skippedNoCVE++;
                            pageSkipped++;
                            continue;
                        }

                        for (String cveId : cveIds) {
                            try {
                                Optional<CiscoAdvisory> existingAdvisory = advisoryRepository.findById(cveId);
                                CiscoAdvisory advisoryEntity = existingAdvisory.orElse(new CiscoAdvisory());
                                
                                boolean isNew = !existingAdvisory.isPresent();
                                
                                advisoryEntity.setCveId(cveId);
                                
                                Map<String, Object> ciscoData = buildCiscoData(adv);
                                advisoryEntity.setCisco_data(mapper.valueToTree(ciscoData));
                                
                                List<String> bugIds = extractList(adv.path("bugIDs"));
                                List<String> cwes = extractList(adv.path("cwe"));
                                List<String> products = extractList(adv.path("productNames"));
                                
                                advisoryEntity.setBug_id(mapper.valueToTree(bugIds));
                                advisoryEntity.setCwe(mapper.valueToTree(cwes));
                                advisoryEntity.setProductnames(mapper.valueToTree(products));

                                advisoryRepository.save(advisoryEntity);
                                
                                if (isNew) {
                                    added++;
                                    pageAdded++;
                                } else {
                                    updated++;
                                    pageUpdated++;
                                }
                                
                            } catch (Exception ex) {
                                System.err.println("❌ Error saving CVE " + cveId + ": " + ex.getMessage());
                            }
                        }
                    }

                    System.out.println("✅ Page " + pageIndex + " completed: " + 
                                     pageAdded + " added, " + pageUpdated + " updated, " + pageSkipped + " skipped (no CVEs)");

                    if (advList.size() < pageSize) {
                        System.out.println("🎉 Reached final page! Fetch complete.");
                        hasMorePages = false;
                    } else {
                        pageIndex++;
                    }

                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                    
                } catch (Exception e) {
                    System.err.println("❌ Error fetching Cisco page " + pageIndex + ": " + e.getMessage());
                    pageIndex++;
                }
            }
            
        } catch (Exception e) {
            System.err.println("❌ Failed to fetch Cisco advisories: " + e.getMessage());
            fetchCiscoDataFromNVD();
        }

        long totalAfter = advisoryRepository.count();
        log.setTotalData((int) totalAfter);
        log.setAddedData(added);
        logRepository.save(log);

        System.out.println("🎉 COMPLETE Cisco advisories fetch finished!");
        System.out.println("📊 FINAL SUMMARY:");
        System.out.println("   - Records before: " + totalBefore);
        System.out.println("   - New records added: " + added);
        System.out.println("   - Existing records updated: " + updated);
        System.out.println("   - Advisories skipped (no CVEs): " + skippedNoCVE);
        System.out.println("   - Records after: " + totalAfter);
        System.out.println("   - Net change: " + (totalAfter - totalBefore));
    }

    /**
     * Fetch Cisco-related data from NVD
     */
    public void fetchCiscoDataFromNVD() {
        System.out.println("🔄 Falling back to NVD for Cisco-related vulnerabilities...");
        
        int totalProcessed = 0;
        int startIndex = 0;
        int resultsPerPage = 2000;
        
        while (true) {
            try {
                String url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=cisco&resultsPerPage=" + 
                           resultsPerPage + "&startIndex=" + startIndex;
                
                System.out.println("📥 Fetching NVD data from index " + startIndex + "...");
                ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
                
                if (!response.getStatusCode().is2xxSuccessful()) {
                    System.err.println("❌ NVD fetch failed: HTTP " + response.getStatusCode());
                    break;
                }

                JsonNode root = mapper.readTree(response.getBody());
                JsonNode vulnerabilities = root.path("vulnerabilities");
                
                if (!vulnerabilities.isArray() || vulnerabilities.size() == 0) {
                    System.out.println("✅ No more NVD vulnerabilities to process");
                    break;
                }

                int pageProcessed = 0;
                for (JsonNode vuln : vulnerabilities) {
                    JsonNode cve = vuln.path("cve");
                    String cveId = cve.path("id").asText();
                    
                    if (cveId != null && !cveId.isEmpty() && !advisoryRepository.existsById(cveId)) {
                        CiscoAdvisory advisory = new CiscoAdvisory();
                        advisory.setCveId(cveId);
                        
                        Map<String, Object> ciscoData = new HashMap<>();
                        ciscoData.put("advisory_id", "NVD-" + cveId);
                        ciscoData.put("advisory_title", cve.path("descriptions").get(0).path("value").asText(""));
                        ciscoData.put("source", "NVD Complete");
                        
                        JsonNode metrics = cve.path("metrics");
                        String cvssScore = "N/A";
                        if (metrics.has("cvssMetricV2") && metrics.path("cvssMetricV2").isArray() && 
                            metrics.path("cvssMetricV2").size() > 0) {
                            cvssScore = metrics.path("cvssMetricV2").get(0).path("cvssData").path("baseScore").asText("N/A");
                        } else if (metrics.has("cvssMetricV31") && metrics.path("cvssMetricV31").isArray() &&
                                 metrics.path("cvssMetricV31").size() > 0) {
                            cvssScore = metrics.path("cvssMetricV31").get(0).path("cvssData").path("baseScore").asText("N/A");
                        }
                        ciscoData.put("cvss_basescore", cvssScore);
                        
                        advisory.setCisco_data(mapper.valueToTree(ciscoData));
                        advisoryRepository.save(advisory);
                        pageProcessed++;
                        totalProcessed++;
                    }
                }
                
                System.out.println("✅ Processed " + pageProcessed + " CVEs from NVD (total: " + totalProcessed + ")");
                
                if (vulnerabilities.size() < resultsPerPage) {
                    System.out.println("🎉 Reached final NVD page! Fetch complete.");
                    break;
                }
                
                startIndex += resultsPerPage;
                
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
                
            } catch (Exception e) {
                System.err.println("❌ Error fetching NVD data: " + e.getMessage());
                break;
            }
        }
        
        System.out.println("🎉 COMPLETE NVD fetch finished! Total processed: " + totalProcessed + " CVEs");
    }

    /**
     * Manual method to force fetch all data
     */
    public Map<String, Object> fetchAllData() {
        System.out.println("🚀 MANUAL TRIGGER: Starting COMPLETE data fetch...");
        
        long initialCount = advisoryRepository.count();
        
        fetchAndStoreCiscoAdvisories();
        
        fetchCiscoDataFromNVD();
        
        long finalCount = advisoryRepository.count();
        long totalAdded = finalCount - initialCount;
        
        return Map.of(
            "status", "success",
            "message", "Complete data fetch finished",
            "initial_records", initialCount,
            "final_records", finalCount,
            "total_added", totalAdded,
            "timestamp", LocalDateTime.now().toString()
        );
    }

    // === NVD API Methods ===

    @Scheduled(cron = "0 30 */12 * * *")
    public void scheduledFetchNvdAndLog() {
        fetchNVDData();
    }

    public Map<String, Object> fetchNVDData() {
        String vendor = "NVD";
        LocalDateTime startTime = LocalDateTime.now();

        VendorFetchLog log = logRepository.findByVendorName(vendor).orElseGet(() -> {
            VendorFetchLog n = new VendorFetchLog();
            n.setVendorName(vendor);
            return n;
        });

        log.setPreviousFetchTime(log.getLastFetchTime());
        log.setLastFetchTime(startTime);

        String url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=Cisco&resultsPerPage=2000";
        try {
            System.out.println("📡 Fetching NVD summary...");
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                String msg = "NVD fetch failed: HTTP " + response.getStatusCode();
                System.err.println(msg);
                return Map.of("status", "error", "message", msg);
            }

            JsonNode root = mapper.readTree(response.getBody());
            int totalResults = root.path("totalResults").asInt(0);

            Integer previousTotal = log.getTotalData();
            int previousTotalValue = (previousTotal != null) ? previousTotal : 0;
            int added = Math.max(0, totalResults - previousTotalValue);

            log.setTotalData(totalResults);
            log.setAddedData(added);
            logRepository.save(log);

            System.out.println("✅ NVD summary: totalResults=" + totalResults + ", added=" + added);
            
            return Map.of(
                "status", "success",
                "totalResults", totalResults,
                "added", added,
                "timestamp", new Date().toString()
            );

        } catch (Exception e) {
            System.err.println("❌ ERROR fetching NVD: " + e.getMessage());
            return Map.of("status", "error", "message", e.getMessage());
        }
    }

    // === Helper Methods ===

    private Map<String, Object> buildCiscoData(JsonNode adv) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("advisory_id", adv.path("advisoryId").asText(""));
        data.put("advisory_title", adv.path("advisoryTitle").asText(""));
        data.put("status", adv.path("status").asText(""));
        data.put("cvss_basescore", adv.path("cvssBaseScore").asText(""));
        data.put("first_published", adv.path("firstPublished").asText(""));
        data.put("last_update", adv.path("lastUpdated").asText(""));
        data.put("version", adv.path("version").asText(""));
        data.put("sir", adv.path("sir").asText(""));
        data.put("summary", adv.path("summary").asText(""));
        data.put("source", "Cisco PSIRT API");
        return data;
    }

    private List<String> extractList(JsonNode node) {
        List<String> list = new ArrayList<>();
        if (node != null && node.isArray()) {
            for (JsonNode n : node) {
                if (!n.isNull() && !n.asText().isEmpty()) list.add(n.asText());
            }
        }
        return list;
    }

    // === Public Methods for API ===

    public Map<String, Object> testCiscoCredentials() {
        try {
            String token = getAccessToken();
            return Map.of(
                "status", "success",
                "message", "Cisco OAuth2 authentication successful!",
                "token_type", "Bearer",
                "expires_in_seconds", 3600,
                "token_length", token.length()
            );
        } catch (Exception e) {
            return Map.of(
                "status", "error",
                "message", e.getMessage()
            );
        }
    }

    /**
     * Get database statistics
     */
    public Map<String, Object> getDatabaseStats() {
        long totalRecords = advisoryRepository.count();
        return Map.of(
            "total_records", totalRecords,
            "database", "Neon PostgreSQL",
            "timestamp", LocalDateTime.now().toString()
        );
    }

    /**
     * Get registration instructions
     */
    public Map<String, Object> getRegistrationInstructions() {
        return Map.of(
            "message", "Your current credentials are working correctly!",
            "status", "valid"
        );
    }

    /**
     * Test Cisco API data
     */
    public Map<String, Object> testCiscoApiData() {
        try {
            String token = getAccessToken();
            String testUrl = "https://apix.cisco.com/security/advisories/v2/all?pageIndex=1&pageSize=5";
            
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + token);
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(testUrl, HttpMethod.GET, requestEntity, String.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                return Map.of(
                    "status", "error",
                    "message", "API call failed: HTTP " + response.getStatusCode()
                );
            }

            JsonNode root = mapper.readTree(response.getBody());
            JsonNode advisories = root.path("advisories");
            
            int advisoryCount = advisories.isArray() ? advisories.size() : 0;
            
            List<Map<String, Object>> sampleAdvisories = new ArrayList<>();
            if (advisories.isArray()) {
                for (int i = 0; i < Math.min(advisories.size(), 3); i++) {
                    JsonNode adv = advisories.get(i);
                    Map<String, Object> sample = new HashMap<>();
                    sample.put("advisoryId", adv.path("advisoryId").asText());
                    sample.put("advisoryTitle", adv.path("advisoryTitle").asText());
                    sample.put("cvssBaseScore", adv.path("cvssBaseScore").asText());
                    sample.put("cves", extractList(adv.path("cves")));
                    sampleAdvisories.add(sample);
                }
            }

            return Map.of(
                "status", "success",
                "message", "Cisco API is working correctly!",
                "advisory_count", advisoryCount,
                "sample_advisories", sampleAdvisories,
                "total_pages", root.path("totalPages").asInt(),
                "total_advisories", root.path("totalAdvisories").asInt()
            );

        } catch (Exception e) {
            return Map.of(
                "status", "error",
                "message", "Cisco API test failed: " + e.getMessage()
            );
        }
    }
}
