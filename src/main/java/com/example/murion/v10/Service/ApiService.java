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

import javax.net.ssl.*;
import java.time.LocalDateTime;
import java.util.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

@Service
public class ApiService {

    private final RestTemplate restTemplate;
    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private CiscoAdvisoryRepository advisoryRepository;

    @Autowired
    private VendorFetchLogRepository logRepository;

    // Cisco OAuth2 Credentials - Consider moving to application.properties
    private static final String CLIENT_ID = "q37wu5ga3695r3jfzccnfp8q";
    private static final String CLIENT_SECRET = "aB54S9PgZuTD87TpumQPw2Yq";
    private static final String TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token";

    private String accessToken;
    private LocalDateTime tokenExpiry;

    public ApiService() {
        this.restTemplate = createUnsafeRestTemplate();
    }

    private RestTemplate createUnsafeRestTemplate() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod) {
                    if (connection instanceof HttpsURLConnection https) {
                        https.setSSLSocketFactory(sslSocketFactory);
                        https.setHostnameVerifier((hostname, session) -> true);
                    }
                }
            };
            
            // Set timeouts
            factory.setConnectTimeout(30000);
            factory.setReadTimeout(30000);
            
            return new RestTemplate(factory);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create RestTemplate with disabled SSL", e);
        }
    }

    // === Diagnostic Methods ===

    /**
     * Comprehensive diagnosis of Cisco OAuth2 authentication
     */
    public Map<String, Object> diagnoseCiscoAuth() {
        Map<String, Object> diagnosis = new LinkedHashMap<>();
        List<String> logs = new ArrayList<>();
        
        logs.add("🔍 Starting Cisco OAuth Diagnosis...");
        logs.add("Token URL: " + TOKEN_URL);
        logs.add("Client ID: " + CLIENT_ID);
        logs.add("Client Secret: " + (CLIENT_SECRET != null ? CLIENT_SECRET.substring(0, 4) + "***" : "null"));
        
        try {
            // Test 1: Basic connectivity
            logs.add("📡 Testing basic connectivity to id.cisco.com...");
            try {
                ResponseEntity<String> connectivityTest = restTemplate.getForEntity("https://id.cisco.com", String.class);
                logs.add("✅ Basic connectivity: HTTP " + connectivityTest.getStatusCode());
                diagnosis.put("connectivity", "SUCCESS - HTTP " + connectivityTest.getStatusCode());
            } catch (Exception e) {
                logs.add("❌ Basic connectivity failed: " + e.getMessage());
                diagnosis.put("connectivity", "FAILED - " + e.getMessage());
            }

            // Test 2: Form URL encoded request (standard approach)
            logs.add("🔄 Testing OAuth2 token request with form parameters...");
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                headers.set("User-Agent", "Mozilla/5.0 (compatible; SecurityApp/1.0)");
                
                MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
                body.add("grant_type", "client_credentials");
                body.add("client_id", CLIENT_ID);
                body.add("client_secret", CLIENT_SECRET);

                HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
                
                logs.add("Request details:");
                logs.add("  - Method: POST");
                logs.add("  - Content-Type: " + headers.getContentType());
                logs.add("  - Body parameters: grant_type, client_id, client_secret");

                ResponseEntity<String> response = restTemplate.postForEntity(TOKEN_URL, request, String.class);
                
                if (response.getStatusCode().is2xxSuccessful()) {
                    JsonNode responseBody = mapper.readTree(response.getBody());
                    String token = responseBody.path("access_token").asText();
                    int expiresIn = responseBody.path("expires_in").asInt();
                    
                    logs.add("✅ OAuth2 SUCCESS - Token obtained, length: " + (token != null ? token.length() : 0));
                    logs.add("✅ Token expires in: " + expiresIn + " seconds");
                    
                    diagnosis.put("oauth2_form_params", "SUCCESS");
                    diagnosis.put("token_length", token != null ? token.length() : 0);
                    diagnosis.put("expires_in", expiresIn);
                } else {
                    logs.add("❌ OAuth2 FAILED - HTTP " + response.getStatusCode());
                    logs.add("❌ Response: " + response.getBody());
                    
                    diagnosis.put("oauth2_form_params", "FAILED - HTTP " + response.getStatusCode());
                    diagnosis.put("response_body", response.getBody());
                }
            } catch (Exception e) {
                logs.add("❌ OAuth2 request failed: " + e.getMessage());
                diagnosis.put("oauth2_form_params", "FAILED - " + e.getMessage());
            }

            // Test 3: Try with different RestTemplate (without SSL bypass)
            logs.add("🔄 Testing with standard RestTemplate (no SSL bypass)...");
            try {
                RestTemplate normalTemplate = new RestTemplate();
                normalTemplate.setRequestFactory(new SimpleClientHttpRequestFactory());
                
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                
                MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
                body.add("grant_type", "client_credentials");
                body.add("client_id", CLIENT_ID);
                body.add("client_secret", CLIENT_SECRET);

                HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
                
                ResponseEntity<String> response = normalTemplate.postForEntity(TOKEN_URL, request, String.class);
                
                if (response.getStatusCode().is2xxSuccessful()) {
                    logs.add("✅ Standard RestTemplate SUCCESS - HTTP " + response.getStatusCode());
                    diagnosis.put("standard_resttemplate", "SUCCESS");
                } else {
                    logs.add("❌ Standard RestTemplate FAILED - HTTP " + response.getStatusCode());
                    diagnosis.put("standard_resttemplate", "FAILED - HTTP " + response.getStatusCode());
                }
            } catch (Exception e) {
                logs.add("❌ Standard RestTemplate failed: " + e.getMessage());
                diagnosis.put("standard_resttemplate", "FAILED - " + e.getMessage());
            }

        } catch (Exception e) {
            logs.add("💥 Diagnosis failed with exception: " + e.getMessage());
            diagnosis.put("diagnosis_error", e.getMessage());
        }

        diagnosis.put("logs", logs);
        diagnosis.put("timestamp", LocalDateTime.now().toString());
        
        return diagnosis;
    }

    /**
     * Get registration instructions for Cisco API
     */
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

    /**
     * Test Cisco credentials specifically
     */
    public Map<String, Object> testCiscoCredentials() {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.set("User-Agent", "SecurityApp-Diagnostic/1.0");
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "client_credentials");
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            System.out.println("🔑 Testing Cisco credentials...");
            System.out.println("URL: " + TOKEN_URL);
            System.out.println("Client ID: " + CLIENT_ID);

            ResponseEntity<String> response = restTemplate.postForEntity(TOKEN_URL, request, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                JsonNode tokenResponse = mapper.readTree(response.getBody());
                String token = tokenResponse.path("access_token").asText();
                int expiresIn = tokenResponse.path("expires_in").asInt();
                String tokenType = tokenResponse.path("token_type").asText();
                String scope = tokenResponse.path("scope").asText();
                
                System.out.println("✅ SUCCESS: Token obtained successfully");
                
                return Map.of(
                    "status", "success",
                    "message", "Credentials are valid and working",
                    "token_type", tokenType,
                    "expires_in_seconds", expiresIn,
                    "scope", scope,
                    "token_length", token != null ? token.length() : 0,
                    "next_steps", "You can now use the token to access Cisco PSIRT API"
                );
            } else {
                System.err.println("❌ FAILED: HTTP " + response.getStatusCode());
                
                return Map.of(
                    "status", "error",
                    "http_status", response.getStatusCode().toString(),
                    "response_body", response.getBody(),
                    "message", "Authentication failed. Check your application registration.",
                    "possible_causes", Arrays.asList(
                        "Application not properly registered in Cisco API Console",
                        "Application type is not 'Service'",
                        "Grant type is not 'Client Credentials'", 
                        "Not subscribed to Cisco PSIRT openVuln API",
                        "Credentials are deprecated and need migration"
                    )
                );
            }
        } catch (Exception e) {
            System.err.println("❌ EXCEPTION: " + e.getMessage());
            
            return Map.of(
                "status", "error",
                "message", e.getMessage(),
                "possible_solutions", Arrays.asList(
                    "Verify your application registration at https://apiconsole.cisco.com/",
                    "Check if your application needs migration",
                    "Ensure you're using the correct Client ID and Secret",
                    "Try registering a new application with type 'Service'"
                )
            );
        }
    }

    // === Cisco API Methods ===

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
     * Fetch and store Cisco advisories - with improved error handling
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
            // Test authentication first
            String token = getAccessToken();
            System.out.println("✅ Authentication successful, proceeding with data fetch...");
            
            // Your existing Cisco fetch logic here
            String baseUrl = "https://apix.cisco.com/security/advisories/v2/all";
            int pageIndex = 1, pageSize = 10; // Reduced for testing
            
            boolean hasMorePages = true;
            
            while (hasMorePages) {
                try {
                    String url = baseUrl + "?pageIndex=" + pageIndex + "&pageSize=" + pageSize;
                    HttpHeaders headers = new HttpHeaders();
                    headers.set("Authorization", "Bearer " + token);
                    headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);

                    HttpEntity<String> requestEntity = new HttpEntity<>(headers);
                    ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);

                    if (!response.getStatusCode().is2xxSuccessful()) {
                        System.err.println("Failed to fetch Cisco page " + pageIndex + ": HTTP " + response.getStatusCode());
                        System.err.println("Response: " + response.getBody());
                        break;
                    }

                    JsonNode root = mapper.readTree(response.getBody());
                    JsonNode advList = root.path("advisories");
                    
                    if (!advList.isArray() || advList.isEmpty()) {
                        System.out.println("No more advisories to fetch");
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
            // Don't throw exception to allow NVD to continue
        }

        log.setTotalData((int) advisoryRepository.count());
        log.setAddedData(added);
        logRepository.save(log);

        System.out.println("✅ Cisco advisories update completed. Added: " + added + 
                         " (before: " + totalBefore + ", after: " + advisoryRepository.count() + ")");
    }

    /**
     * Fallback method to fetch Cisco-related data from NVD when Cisco API fails
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
}
