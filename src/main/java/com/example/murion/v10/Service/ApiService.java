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
        // Use standard RestTemplate without SSL bypass
        this.restTemplate = createRestTemplate();
    }

    private RestTemplate createRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        // Set timeouts
        factory.setConnectTimeout(30000);
        factory.setReadTimeout(30000);
        return new RestTemplate(factory);
    }

    // === Cisco OAuth2 Token Methods ===

    /**
     * Get OAuth2 access token from Cisco
     */
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
                String errorMsg = "Token request failed: HTTP " + response.getStatusCode() + " - " + response.getBody();
                System.err.println(errorMsg);
                throw new RuntimeException(errorMsg);
            }

            JsonNode tokenResponse = mapper.readTree(response.getBody());
            accessToken = tokenResponse.path("access_token").asText(null);
            int expiresIn = tokenResponse.path("expires_in").asInt(3600);
            tokenExpiry = LocalDateTime.now().plusSeconds(Math.max(expiresIn - 60, 30));

            if (accessToken == null || accessToken.isEmpty()) {
                throw new RuntimeException("Token response missing access_token: " + response.getBody());
            }

            System.out.println("✅ New Cisco access token obtained (expires in " + expiresIn + "s)");
            return accessToken;
        } catch (Exception e) {
            System.err.println("❌ Failed to obtain Cisco OAuth2 token: " + e.getMessage());
            throw new RuntimeException("Failed to obtain Cisco OAuth2 token: " + e.getMessage(), e);
        }
    }

    /**
     * Test Cisco credentials with detailed error handling
     */
    public Map<String, Object> testCiscoCredentials() {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "client_credentials");
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            System.out.println("🔑 Testing Cisco credentials with standard RestTemplate...");
            
            ResponseEntity<String> response = restTemplate.postForEntity(TOKEN_URL, request, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                JsonNode tokenResponse = mapper.readTree(response.getBody());
                String token = tokenResponse.path("access_token").asText();
                int expiresIn = tokenResponse.path("expires_in").asInt();
                
                return Map.of(
                    "status", "success",
                    "message", "Cisco OAuth2 authentication successful!",
                    "token_type", tokenResponse.path("token_type").asText(),
                    "expires_in_seconds", expiresIn,
                    "token_length", token != null ? token.length() : 0,
                    "scope", tokenResponse.path("scope").asText("")
                );
            } else {
                return Map.of(
                    "status", "error",
                    "http_status", response.getStatusCode().toString(),
                    "response_body", response.getBody(),
                    "message", "Authentication failed - Application may not be properly registered",
                    "solution", "Please register a new application at https://apiconsole.cisco.com/ with type 'Service' and grant type 'Client Credentials'"
                );
            }
        } catch (Exception e) {
            return Map.of(
                "status", "error",
                "message", e.getMessage(),
                "solution", "Your current credentials are not working. Please register a new application in Cisco API Console."
            );
        }
    }

    // === Cisco Advisory Methods ===

    /**
     * Fetch and store Cisco advisories
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
        long totalBefore = advisoryRepository.count();

        System.out.println("🚀 Starting Cisco advisories fetch...");

        try {
            // Get access token first
            String token = getAccessToken();
            System.out.println("✅ Authentication successful, starting data fetch...");
            
            // Fetch advisories from Cisco API
            String baseUrl = "https://apix.cisco.com/security/advisories/v2/all";
            int pageIndex = 1, pageSize = 10; // Start with small page size for testing

            boolean hasMorePages = true;
            
            while (hasMorePages && pageIndex <= 5) { // Limit to 5 pages for initial testing
                try {
                    String url = baseUrl + "?pageIndex=" + pageIndex + "&pageSize=" + pageSize;
                    HttpHeaders headers = new HttpHeaders();
                    headers.set("Authorization", "Bearer " + token);
                    headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

                    HttpEntity<String> requestEntity = new HttpEntity<>(headers);
                    ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);

                    if (!response.getStatusCode().is2xxSuccessful()) {
                        System.err.println("❌ Failed to fetch Cisco page " + pageIndex + ": HTTP " + response.getStatusCode());
                        break;
                    }

                    JsonNode root = mapper.readTree(response.getBody());
                    JsonNode advList = root.path("advisories");
                    
                    if (!advList.isArray() || advList.isEmpty()) {
                        System.out.println("✅ No more advisories to fetch");
                        hasMorePages = false;
                        break;
                    }

                    System.out.println("📄 Processing page " + pageIndex + " with " + advList.size() + " advisories");

                    for (JsonNode adv : advList) {
                        String advisoryId = adv.path("advisoryId").asText(null);
                        if (advisoryId == null) continue;

                        List<String> cveIds = extractList(adv.path("cves"));
                        if (cveIds.isEmpty()) {
                            System.out.println("⚠️ Advisory " + advisoryId + " has no CVEs, skipping");
                            continue;
                        }

                        // Process each CVE
                        for (String cveId : cveIds) {
                            try {
                                CiscoAdvisory advisoryEntity = advisoryRepository.findById(cveId).orElse(new CiscoAdvisory());
                                advisoryEntity.setCveId(cveId);
                                
                                Map<String, Object> ciscoData = buildCiscoData(adv);
                                advisoryEntity.setCisco_data(mapper.valueToTree(ciscoData));
                                
                                List<String> bugIds = extractList(adv.path("bugIDs"));
                                List<String> cwes = extractList(adv.path("cwe"));
                                List<String> products = extractList(adv.path("productNames"));
                                
                                advisoryEntity.setBug_id(mapper.valueToTree(bugIds));
                                advisoryEntity.setCwe(mapper.valueToTree(cwes));
                                advisoryEntity.setProductnames(mapper.valueToTree(products));

                                // Try to fetch CSAF data
                                String csafUrl = "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/"
                                        + advisoryId + "/csaf/" + advisoryId + ".json";
                                JsonNode csafData = fetchCsafData(csafUrl, token);
                                if (csafData != null && !csafData.isEmpty()) {
                                    advisoryEntity.setCsaf(csafData);
                                }

                                boolean existsBefore = advisoryRepository.existsById(cveId);
                                advisoryRepository.save(advisoryEntity);
                                if (!existsBefore) added++;
                                
                                System.out.println("💾 Saved CVE: " + cveId + " from advisory: " + advisoryId);
                            } catch (Exception ex) {
                                System.err.println("❌ Error saving CVE " + cveId + ": " + ex.getMessage());
                            }
                        }
                    }

                    if (advList.size() < pageSize) {
                        System.out.println("✅ Reached last page");
                        hasMorePages = false;
                    }
                    pageIndex++;

                } catch (Exception e) {
                    System.err.println("❌ Error fetching Cisco page " + pageIndex + ": " + e.getMessage());
                    hasMorePages = false;
                    break;
                }
            }
            
        } catch (Exception e) {
            System.err.println("❌ Failed to fetch Cisco advisories: " + e.getMessage());
            // Fall back to NVD data
            fetchCiscoDataFromNVD();
        }

        log.setTotalData((int) advisoryRepository.count());
        log.setAddedData(added);
        logRepository.save(log);

        System.out.println("✅ Cisco advisories update completed. Added: " + added + 
                         " (before: " + totalBefore + ", after: " + advisoryRepository.count() + ")");
    }

    /**
     * Fetch CSAF data for an advisory
     */
    private JsonNode fetchCsafData(String csafUrl, String token) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
            headers.set("Authorization", "Bearer " + token);
            
            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(csafUrl, HttpMethod.GET, requestEntity, String.class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                return mapper.readTree(response.getBody());
            } else {
                System.err.println("⚠️ CSAF fetch failed (" + csafUrl + "): HTTP " + response.getStatusCode());
                return mapper.createObjectNode();
            }
        } catch (Exception e) {
            System.err.println("⚠️ CSAF fetch failed for " + csafUrl + ": " + e.getMessage());
            return mapper.createObjectNode();
        }
    }

    /**
     * Fallback method to fetch Cisco-related data from NVD
     */
    public void fetchCiscoDataFromNVD() {
        System.out.println("🔄 Falling back to NVD for Cisco-related vulnerabilities...");
        
        String url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=cisco&resultsPerPage=50";
        
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                JsonNode root = mapper.readTree(response.getBody());
                JsonNode vulnerabilities = root.path("vulnerabilities");
                
                int processed = 0;
                for (JsonNode vuln : vulnerabilities) {
                    JsonNode cve = vuln.path("cve");
                    String cveId = cve.path("id").asText();
                    
                    if (cveId != null && !cveId.isEmpty()) {
                        CiscoAdvisory advisory = advisoryRepository.findById(cveId).orElse(new CiscoAdvisory());
                        advisory.setCveId(cveId);
                        
                        // Create basic Cisco data structure from NVD data
                        Map<String, Object> ciscoData = new HashMap<>();
                        ciscoData.put("advisory_id", "NVD-" + cveId);
                        ciscoData.put("advisory_title", cve.path("descriptions").get(0).path("value").asText(""));
                        ciscoData.put("source", "NVD Fallback");
                        ciscoData.put("cvss_basescore", 
                            cve.path("metrics").path("cvssMetricV2").get(0).path("cvssData").path("baseScore").asText("N/A"));
                        
                        advisory.setCisco_data(mapper.valueToTree(ciscoData));
                        advisoryRepository.save(advisory);
                        processed++;
                    }
                }
                
                System.out.println("✅ Processed " + processed + " Cisco-related CVEs from NVD");
            }
        } catch (Exception e) {
            System.err.println("❌ Error fetching Cisco data from NVD: " + e.getMessage());
        }
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

        String url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=Cisco&resultsPerPage=100";
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
            
            Map<String, Object> summary = new HashMap<>();
            summary.put("status", "success");
            summary.put("totalResults", totalResults);
            summary.put("added", added);
            summary.put("timestamp", new Date().toString());
            return summary;

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

    // === Registration Help Method ===

    public Map<String, Object> getRegistrationInstructions() {
        return Map.of(
            "registration_steps", Arrays.asList(
                "1. Go to: https://apiconsole.cisco.com/",
                "2. Login with your Cisco account (create one if needed)",
                "3. Click on 'My Apps & Keys' in the top navigation",
                "4. Click 'Register a New App' button",
                "5. Fill in the application details:",
                "   - Application Name: YourAppName-Service",
                "   - Application Type: SELECT 'Service'",
                "   - Grant Type: SELECT 'Client Credentials'", 
                "   - API Subscriptions: SELECT 'Cisco PSIRT openVuln API'",
                "   - Description: (Optional) Your application description",
                "   - Agree to terms of service",
                "6. Click 'Register'",
                "7. Copy the new Client ID and Client Secret",
                "8. Update your application configuration with new credentials"
            ),
            "important_notes", Arrays.asList(
                "⚠️  Current registered applications might be deprecated - you may need to migrate",
                "⚠️  Application Type MUST be 'Service' (not 'Web' or other types)",
                "⚠️  Grant Type MUST be 'Client Credentials'",
                "⚠️  Make sure you subscribe to 'Cisco PSIRT openVuln API'",
                "⚠️  Keep your Client Secret secure and never commit to version control"
            ),
            "troubleshooting_resources", Arrays.asList(
                "Cisco PSIRT API Documentation: https://developer.cisco.com/docs/psirt/",
                "API Migration Guide: https://developer.cisco.com/docs/psirt/#!migrating-applications",
                "Getting Started: https://developer.cisco.com/docs/psirt/#!getting-started"
            )
        );
    }
}
