package com.example.murion.v10.Service;

import com.example.murion.v10.Entity.CiscoAdvisory;
import com.example.murion.v10.Repository.CiscoAdvisoryRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

@Service
public class ApiService {

    private final RestTemplate restTemplate;
    private final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private CiscoAdvisoryRepository repository;

    private static final String CISCO_API_TOKEN = "eyJraWQiOiJqNHJGLWx1WW5jRjF1d0VQU01OVDd5OHV2Q1NDMGRXM2xRSFJra3QxM3JBIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULlNaY1dQSGlaMWx2bERzYUNWX2dXVGZxNGV5WTFtV19sWGpkTFJ6a1daN0UiLCJpc3MiOiJodHRwczovL2lkLmNpc2NvLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE3NjEyODIwNzcsImV4cCI6MTc2MTI4NTY3NywiY2lkIjoicTM3d3U1Z2EzNjk1cjNqZnpjY25mcDhxIiwic2NwIjpbImN1c3RvbXNjb3BlIl0sInN1YiI6InEzN3d1NWdhMzY5NXIzamZ6Y2NuZnA4cSIsImF6cCI6InEzN3d1NWdhMzY5NXIzamZ6Y2NuZnA4cSJ9.l2ayScEzHSyUqoJeZFGf_odyiezecFwE8-8EIzWBZaBf1zWPvlNYDLQ-RHw0TkwbLhXWjAHCTOxjtt_izHe-81G7B0hz2LGSgpPiX7UYPN4C4b2jGDcxInD3KASf3DYKbwHn2gmch2YG4W_qk0sEbA1HTo2MJQ3AGDy3wlXsosZUxzbjFy9TfMPLaDTlGUHZBuE6ypE7Cc2vwEPvrSmyUypie9Sfw3WWVklhu01rAgl2TVuQ7XNCTtzwVblzvkydRv4MZSgQX6cceETAiKjCgWI-GIoG-c8jAOomtuH59dv9YTO8QPKkryYIRZqgLWT09lhTXzsZ4HyMZogcMcwi-g";

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

            SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod) {
                    if (connection instanceof HttpsURLConnection httpsConnection) {
                        httpsConnection.setSSLSocketFactory(sslSocketFactory);
                        httpsConnection.setHostnameVerifier((hostname, session) -> true);
                    }
                }
            };
            return new RestTemplate(requestFactory);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create RestTemplate with disabled SSL", e);
        }
    }

    // === Fetch & Store Cisco Advisories ===
    public void fetchAndStoreCiscoAdvisories() {
        String baseUrl = "https://apix.cisco.com/security/advisories/v2/all";
        int pageIndex = 1, pageSize = 100;
        List<JsonNode> allAdvisories = new ArrayList<>();

        System.out.println("🚀 Fetching Cisco advisories...");

        while (true) {
            try {
                String url = baseUrl + "?pageIndex=" + pageIndex + "&pageSize=" + pageSize;
                HttpHeaders headers = new HttpHeaders();
                headers.set("Authorization", "Bearer " + CISCO_API_TOKEN);
                headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
                HttpEntity<String> entity = new HttpEntity<>(headers);

                ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
                JsonNode root = mapper.readTree(response.getBody());
                JsonNode advisories = root.path("advisories");

                if (!advisories.isArray() || advisories.isEmpty()) break;

                advisories.forEach(allAdvisories::add);
                System.out.println("Fetched page " + pageIndex + " with " + advisories.size() + " advisories.");

                if (advisories.size() < pageSize) break;
                pageIndex++;

            } catch (Exception e) {
                System.err.println("❌ Error fetching page " + pageIndex + ": " + e.getMessage());
                break;
            }
        }

        for (JsonNode adv : allAdvisories) {
            String advisoryId = adv.path("advisoryId").asText(null);
            if (advisoryId == null) continue;

            List<String> cveIds = extractList(adv.path("cves"));
            if (cveIds.isEmpty()) continue;

            Map<String, Object> ciscoData = buildCiscoData(adv);
            List<String> bugIds = extractList(adv.path("bugIDs"));
            List<String> cwes = extractList(adv.path("cwe"));
            List<String> products = extractList(adv.path("productNames"));

            String csafUrl =
                    "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/"
                            + advisoryId + "/csaf/" + advisoryId + ".json";

            JsonNode csafData = fetchCsafData(csafUrl);
            if (csafData == null || csafData.isEmpty()) continue;

            // In your fetchAndStoreCiscoAdvisories method, replace this section:
            for (String cveId : cveIds) {
                try {
                    JsonNode vulns = csafData.path("vulnerabilities");
                    ArrayNode filtered = mapper.createArrayNode();

                    if (vulns.isArray()) {
                        for (JsonNode v : vulns) {
                            String cveField = v.has("cve") ? v.get("cve").asText() : v.path("cveid").asText();
                            if (cveField.equalsIgnoreCase(cveId)) filtered.add(v);
                        }
                    }
                    ((ObjectNode) csafData).set("vulnerabilities", filtered);

                    CiscoAdvisory entity = repository.findById(cveId).orElse(new CiscoAdvisory());
                    entity.setCveId(cveId);
                    entity.setCisco_data(mapper.valueToTree(ciscoData)); // Convert Map to JsonNode
                    entity.setBug_id(mapper.valueToTree(bugIds));       // Convert List to JsonNode
                    entity.setCwe(mapper.valueToTree(cwes));           // Convert List to JsonNode
                    entity.setProductnames(mapper.valueToTree(products)); // Convert List to JsonNode
                    entity.setCsaf(csafData);                          // Already JsonNode

                    repository.save(entity);
                    System.out.println("✅ Stored CVE " + cveId + " from " + advisoryId);

                } catch (Exception e) {
                    System.err.println("⚠️ Error saving " + cveId + ": " + e.getMessage());
                    e.printStackTrace(); // Add this for better debugging
                }
            }
        }

        System.out.println("✅ All Cisco advisories processed successfully.");
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

    private JsonNode fetchCsafData(String csafUrl) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
            HttpEntity<String> entity = new HttpEntity<>(headers);
            ResponseEntity<String> response = restTemplate.exchange(csafUrl, HttpMethod.GET, entity, String.class);
            return mapper.readTree(response.getBody());
        } catch (Exception e) {
            System.err.println("⚠️ CSAF fetch failed for " + csafUrl + ": " + e.getMessage());
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
