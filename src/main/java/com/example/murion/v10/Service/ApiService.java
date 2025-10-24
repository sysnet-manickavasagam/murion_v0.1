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
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.HttpsURLConnection;


@Service
public class ApiService {

    private final RestTemplate restTemplate;
    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private CiscoAdvisoryRepository advisoryRepository;

    @Autowired
    private VendorFetchLogRepository logRepository;

    // --- Cisco OAuth2 Credentials ---
    private static final String CLIENT_ID = "q37wu5ga3695r3jfzccnfp8q";
    private static final String CLIENT_SECRET = "aB54S9PgZuTD87TpumQPw2Yq";
    private static final String TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token";

    private String accessToken;
    private LocalDateTime tokenExpiry;

    public ApiService() {
        this.restTemplate = createUnsafeRestTemplate();
    }

    // --- Disable SSL Verification for Cisco API ---
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

    // === Generate Cisco Access Token ===
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

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(TOKEN_URL, entity, String.class);

        JsonNode tokenResponse = mapper.readTree(response.getBody());
        accessToken = tokenResponse.path("access_token").asText();
        int expiresIn = tokenResponse.path("expires_in").asInt(3600);
        tokenExpiry = LocalDateTime.now().plusSeconds(expiresIn - 60);

        System.out.println("New Cisco token generated. Expires in " + expiresIn + " seconds.");
        return accessToken;
    } catch (Exception e) {
        throw new RuntimeException("Failed to obtain Cisco OAuth2 token: " + e.getMessage(), e);
    }
}


    // === Fetch and Store Cisco Advisories ===
    @Scheduled(cron = "0 0 */6 * * *") // every 6 hours
    public void fetchAndStoreCiscoAdvisories() {
        String vendor = "Cisco";
        LocalDateTime startTime = LocalDateTime.now();

        VendorFetchLog log = logRepository.findByVendorName(vendor).orElseGet(() -> {
            VendorFetchLog newLog = new VendorFetchLog();
            newLog.setVendorName(vendor);
            return newLog;
        });

        log.setPreviousFetchTime(log.getLastFetchTime());
        log.setLastFetchTime(startTime);

        int totalBefore = (int) advisoryRepository.count();
        int added = 0;

        String token = getAccessToken();
        String baseUrl = "https://apix.cisco.com/security/advisories/v2/all";
        int pageIndex = 1, pageSize = 100;
        List<JsonNode> advisories = new ArrayList<>();

        System.out.println(" Fetching Cisco advisories...");

        while (true) {
            try {
                String url = baseUrl + "?pageIndex=" + pageIndex + "&pageSize=" + pageSize;
                HttpHeaders headers = new HttpHeaders();
                headers.set("Authorization", "Bearer " + token);
                headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
                HttpEntity<String> entity = new HttpEntity<>(headers);

                ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
                JsonNode root = mapper.readTree(response.getBody());
                JsonNode advList = root.path("advisories");

                if (!advList.isArray() || advList.isEmpty()) break;

                advList.forEach(advisories::add);
                if (advList.size() < pageSize) break;
                pageIndex++;

            } catch (Exception e) {
                System.err.println(" Error fetching page " + pageIndex + ": " + e.getMessage());
                break;
            }
        }

        for (JsonNode adv : advisories) {
            try {
                String advisoryId = adv.path("advisoryId").asText(null);
                if (advisoryId == null) continue;

                List<String> cveIds = extractList(adv.path("cves"));
                if (cveIds.isEmpty()) continue;

                Map<String, Object> ciscoData = buildCiscoData(adv);
                List<String> bugIds = extractList(adv.path("bugIDs"));
                List<String> cwes = extractList(adv.path("cwe"));
                List<String> products = extractList(adv.path("productNames"));

                String csafUrl = "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/"
                        + advisoryId + "/csaf/" + advisoryId + ".json";

                JsonNode csafData = fetchCsafData(csafUrl);
                if (csafData == null || csafData.isEmpty()) continue;

                for (String cveId : cveIds) {
                    if (!advisoryRepository.existsById(cveId)) added++;

                    CiscoAdvisory entity = advisoryRepository.findById(cveId).orElse(new CiscoAdvisory());
                    entity.setCveId(cveId);
                    entity.setCisco_data(mapper.valueToTree(ciscoData));
                    entity.setBug_id(mapper.valueToTree(bugIds));
                    entity.setCwe(mapper.valueToTree(cwes));
                    entity.setProductnames(mapper.valueToTree(products));
                    entity.setCsaf(csafData);
                    advisoryRepository.save(entity);
                }
            } catch (Exception e) {
                System.err.println(" Error saving advisory: " + e.getMessage());
            }
        }

        log.setTotalData((int) advisoryRepository.count());
        log.setAddedData(added);
        logRepository.save(log);

        System.out.println("Cisco advisories updated. Added: " + added);
    }

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

    private JsonNode fetchCsafData(String url) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            return mapper.readTree(response.getBody());
        } catch (Exception e) {
            System.err.println(" CSAF fetch failed for " + url + ": " + e.getMessage());
            return mapper.createObjectNode();
        }
    }


    // --- NVD Fetch ---
    public Map<String, Object> fetchNVDData() {
        String url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=Cisco&resultsPerPage=2000";
        try {
            System.out.println("📡 Fetching NVD data for Cisco...");
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            JsonNode root = mapper.readTree(response.getBody());

            Map<String, Object> summary = new HashMap<>();
            summary.put("status", response.getStatusCode().toString());
            summary.put("totalResults", root.path("totalResults").asInt());
            summary.put("timestamp", new Date().toString());
            return summary;
        } catch (Exception e) {
            System.err.println("❌ ERROR: Unable to fetch NVD data");
            e.printStackTrace();
            return Map.of("error", e.getMessage());
        }
    }
}



