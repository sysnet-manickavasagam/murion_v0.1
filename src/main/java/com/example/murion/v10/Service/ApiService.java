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

    // Cisco OAuth2 Credentials
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
            return new RestTemplate(factory);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create RestTemplate with disabled SSL", e);
        }
    }

    // Test method to verify credentials
    public Map<String, Object> testCiscoCredentials() {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "client_credentials");
            body.add("client_id", CLIENT_ID);
            body.add("client_secret", CLIENT_SECRET);

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(body, headers);

            System.out.println("🔑 Testing Cisco credentials...");
            System.out.println("URL: " + TOKEN_URL);
            System.out.println("Client ID: " + CLIENT_ID);
            System.out.println("Client Secret: " + CLIENT_SECRET.substring(0, 4) + "***");

            ResponseEntity<String> response = restTemplate.postForEntity(TOKEN_URL, requestEntity, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                JsonNode tokenResponse = mapper.readTree(response.getBody());
                String token = tokenResponse.path("access_token").asText();
                int expiresIn = tokenResponse.path("expires_in").asInt();
                
                return Map.of(
                    "status", "success",
                    "message", "Credentials are valid",
                    "token_length", token != null ? token.length() : 0,
                    "expires_in", expiresIn
                );
            } else {
                return Map.of(
                    "status", "error",
                    "message", "HTTP " + response.getStatusCode() + ": " + response.getBody(),
                    "details", "Check if your application is properly registered in Cisco API Console"
                );
            }
        } catch (Exception e) {
            return Map.of(
                "status", "error",
                "message", e.getMessage(),
                "details", "Make sure your application is registered and has access to Cisco PSIRT openVuln API"
            );
        }
    }

    private String getAccessToken() {
        if (accessToken != null && tokenExpiry != null && LocalDateTime.now().isBefore(tokenExpiry)) {
            return accessToken;
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

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

        System.out.println("🚀 Fetching Cisco advisories...");

        try {
            // Test token first
            String token = getAccessToken();
            System.out.println("✅ Token obtained successfully, starting data fetch...");
            
            // Rest of your existing Cisco fetch code here...
            // [Keep the existing fetch logic from your previous implementation]
            
        } catch (Exception e) {
            System.err.println("❌ Failed to fetch Cisco advisories: " + e.getMessage());
        }

        log.setTotalData((int) advisoryRepository.count());
        log.setAddedData(added);
        logRepository.save(log);

        System.out.println("✅ Cisco advisories updated. Added: " + added + " (before: " + totalBefore + ", after: " + advisoryRepository.count() + ")");
    }

    // Add this method to your ApiController to test credentials
    public Map<String, Object> testCredentials() {
        return testCiscoCredentials();
    }

    // Rest of your existing methods (NVD, helpers, etc.)
    // [Keep all your existing NVD and helper methods]
    
    @Scheduled(cron = "0 30 */12 * * *")
    public void scheduledFetchNvdAndLog() {
        fetchNVDData();
    }

    public Map<String, Object> fetchNVDData() {
        // Your existing NVD implementation
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
            int added = (previousTotal != null) ? Math.max(0, totalResults - previousTotal) : totalResults;

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
            e.printStackTrace();
            return Map.of("status", "error", "message", e.getMessage());
        }
    }

    // Your existing helper methods...
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

    private JsonNode fetchCsafData(String csafUrl) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(csafUrl, HttpMethod.GET, requestEntity, String.class);
            if (!response.getStatusCode().is2xxSuccessful()) {
                System.err.println("CSAF fetch failed (" + csafUrl + "): HTTP " + response.getStatusCode());
                return mapper.createObjectNode();
            }
            return mapper.readTree(response.getBody());
        } catch (Exception e) {
            System.err.println("⚠️ CSAF fetch failed for " + csafUrl + ": " + e.getMessage());
            return mapper.createObjectNode();
        }
    }
}
