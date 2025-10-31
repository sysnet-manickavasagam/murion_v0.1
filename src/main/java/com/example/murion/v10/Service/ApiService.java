package com.example.murion.v10.Service;

import com.example.murion.v10.Entity.CiscoAdvisory;
import com.example.murion.v10.Entity.VendorFetchLog;
import com.example.murion.v10.Repository.CiscoAdvisoryRepository;
import com.example.murion.v10.Repository.VendorFetchLogRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

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

    private volatile boolean isFetching = false;
    private volatile int currentProgress = 0;
    private volatile int totalPages = 0;

    @Autowired
    public ApiService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }



    @EventListener(ApplicationReadyEvent.class)
    public void onAppStart() {
        System.out.println("🚀 Application Ready → Fetching Cisco Data...");
        fetchAndStoreCiscoAdvisories();
    }


    private RestTemplate createRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(30000);
        factory.setReadTimeout(30000);
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
            int expiresIn = tokenResponse.path("expires_in").asInt(7200);
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
    // Fetch Cisco advisories
    @Scheduled(cron = "0 0 */2 * * *")
    public void fetchAndStoreCiscoAdvisories() {
        String vendor = "Cisco";
        LocalDateTime startTime = LocalDateTime.now();

        VendorFetchLog log = logRepository.findByVendorName(vendor)
                .orElseGet(() -> { VendorFetchLog v = new VendorFetchLog(); v.setVendorName(vendor); return v; });

        log.setPreviousFetchTime(log.getLastFetchTime());
        log.setLastFetchTime(startTime);

        int added = 0;
        String token = getAccessToken();
        String baseUrl = "https://apix.cisco.com/security/advisories/v2/all";
        int pageIndex = 1, pageSize = 100;
        List<JsonNode> advisories = new ArrayList<>();

        System.out.println("📡 Fetching Cisco advisories...");

        while (true) {
            try {
                String url = baseUrl + "?pageIndex=" + pageIndex + "&pageSize=" + pageSize;
                HttpHeaders headers = new HttpHeaders();
                headers.set("Authorization", "Bearer " + token);
                headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
                HttpEntity<String> requestEntity = new HttpEntity<>(headers);

                ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);
                JsonNode root = mapper.readTree(response.getBody());
                JsonNode advList = root.path("advisories");

                if (!advList.isArray() || advList.isEmpty()) break;

                advList.forEach(advisories::add);
                if (advList.size() < pageSize) break;
                pageIndex++;

            } catch (Exception e) {
                System.err.println("❌ Error fetching Cisco page " + pageIndex + ": " + e.getMessage());
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
                    CiscoAdvisory record = advisoryRepository.findById(cveId).orElse(new CiscoAdvisory());
                    record.setCveId(cveId);
                    record.setCisco_data(mapper.valueToTree(ciscoData));
                    record.setBug_id(mapper.valueToTree(bugIds));
                    record.setCwe(mapper.valueToTree(cwes));
                    record.setProductnames(mapper.valueToTree(products));
                    record.setCsaf(csafData);
                    advisoryRepository.save(record);
                    added++;
                }

            } catch (Exception e) {
                System.err.println("⚠️ Error saving advisory: " + e.getMessage());
            }
        }

        log.setTotalData((int) advisoryRepository.count());
        log.setAddedData(added);
        logRepository.save(log);

        System.out.println("✅ Cisco advisories updated. Added: " + added);
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
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            return mapper.readTree(response.getBody());
        } catch (Exception e) {
            System.err.println("⚠️ CSAF fetch failed for " + url + ": " + e.getMessage());
            return mapper.createObjectNode();
        }
    }

    // === NVD Data Fetch ===
    public Map<String, Object> fetchNVDData() {
        String url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Cisco&resultsPerPage=1000";
        try {
            System.out.println("📡 Fetching NVD CVEs...");
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            JsonNode root = mapper.readTree(response.getBody());

            int total = root.path("totalResults").asInt(0);
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("status", response.getStatusCode().toString());
            summary.put("totalResults", total);
            summary.put("timestamp", new Date().toString());
            return summary;
        } catch (Exception e) {
            e.printStackTrace();
            return Map.of("error", e.getMessage());
        }
    }

}