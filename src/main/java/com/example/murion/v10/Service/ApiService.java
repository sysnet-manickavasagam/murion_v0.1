package com.example.murion.v10.Service;

import com.example.murion.v10.Entity.CiscoAdvisory;
import com.example.murion.v10.Entity.VendorFetchLog;
import com.example.murion.v10.Repository.CiscoAdvisoryRepository;
import com.example.murion.v10.Repository.VendorFetchLogRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import org.springframework.context.event.EventListener;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    @Autowired
    public ApiService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onAppStart() {
        System.out.println("Application Ready → Fetching Cisco Data...");
        fetchAndStoreCiscoAdvisories();
    }

    private RestTemplate createRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(30000);
        factory.setReadTimeout(30000);
        return new RestTemplate(factory);
    }


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

            System.out.println("Requesting Cisco OAuth2 token...");
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

            System.out.println("New Cisco access token obtained (expires in " + expiresIn + "s)");
            return accessToken;
        } catch (Exception e) {
            throw new RuntimeException("Failed to obtain Cisco OAuth2 token: " + e.getMessage(), e);
        }
    }


    @Scheduled(cron = "0 0 */4 * * *")
    public void fetchAndStoreCiscoAdvisories() {

        String vendor = "Cisco";
        LocalDateTime startTimeall = LocalDateTime.now();

        int totalAdded = 0;
        int totalUpdated = 0;



        for (int year = 2025; year >= 1997; year--) {

            final int y = year;

            VendorFetchLog log = logRepository.findByVendorNameAndYear(vendor, String.valueOf(year))
                    .orElseGet(() -> {
                        VendorFetchLog v = new VendorFetchLog();
                        v.setVendorName(vendor);
                        v.setYear(String.valueOf(y));
                        return v;
                    });




            int addedThisYear = 0;
            int yearTotalCount = 0;
            int updatedThisYear = 0;
            System.out.println("Fetching Cisco advisories for year: " + year);

            String baseUrl = "https://apix.cisco.com/security/advisories/v2/year/" + year;

            int pageIndex = 1;
            int pageSize = 100;
            LocalDateTime startTime = LocalDateTime.now();
            log.setPreviousFetchTime(log.getLastFetchTime());
            log.setLastFetchTime(startTime);
            while (pageIndex <= 100) {

                try {
                    String url = baseUrl + "?pageIndex=" + pageIndex + "&pageSize=" + pageSize;

                    HttpHeaders headers = new HttpHeaders();
                    headers.set("Authorization", "Bearer " + getAccessToken());
                    headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
                    HttpEntity<String> requestEntity = new HttpEntity<>(headers);

                    ResponseEntity<String> response = safeCiscoRequest(url, requestEntity);

                    JsonNode root = mapper.readTree(response.getBody());
                    JsonNode advList = root.path("advisories");

                    if (!advList.isArray() || advList.isEmpty())
                        break;

                    for (JsonNode adv : advList) {
                        try {
                            String advisoryId = adv.path("advisoryId").asText();
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

                            for (String cveId : cveIds) {

                                if (cveId == null || cveId.isEmpty()) continue;

                                if (cveId == null || cveId.trim().isEmpty() || cveId.equalsIgnoreCase("NA")) {
                                    System.out.println("SKIPPED - CVE NULL / NA");
                                    continue;
                                }
                                yearTotalCount++;


                                String newLastUpdate = adv.path("lastUpdated").asText("");
                                Optional<CiscoAdvisory> existingOpt = advisoryRepository.findById(cveId);


                                if (existingOpt.isEmpty()) {

                                    CiscoAdvisory record = new CiscoAdvisory();
                                    record.setCveId(cveId);
                                    record.setCisco_data(mapper.valueToTree(ciscoData));
                                    record.setBug_id(mapper.valueToTree(bugIds));
                                    record.setCwe(mapper.valueToTree(cwes));
                                    record.setProductnames(mapper.valueToTree(products));
                                    record.setCsaf(csafData);

                                    advisoryRepository.save(record);

                                    addedThisYear++;
                                    totalAdded++;

                                    System.out.println(cveId + " ADDED" );
                                    continue;
                                }



                                CiscoAdvisory record = existingOpt.get();


                                String oldLastUpdate = record.getCisco_data()
                                        .path("last_update")
                                        .asText("");



                                if (Objects.equals(oldLastUpdate, newLastUpdate)) {
                                    System.out.println(cveId + " SKIPPED (same last_update)");
                                    continue;
                                }



                                try {
                                    LocalDateTime oldDate = LocalDateTime.parse(oldLastUpdate.substring(0, 19));
                                    LocalDateTime newDate = LocalDateTime.parse(newLastUpdate.substring(0, 19));

                                    if (newDate.isBefore(oldDate)) {
                                        System.out.println(cveId + " SKIPPED (incoming data is older)");
                                        continue;
                                    }

                                } catch (Exception e) {
                                    System.out.println("Date parse error → Updating to be safe: " + cveId);
                                }



                                record.setCisco_data(mapper.valueToTree(ciscoData));
                                record.setBug_id(mapper.valueToTree(bugIds));
                                record.setCwe(mapper.valueToTree(cwes));
                                record.setProductnames(mapper.valueToTree(products));
                                record.setCsaf(csafData);

                                advisoryRepository.save(record);
                                updatedThisYear++;
                                totalUpdated++;
                                System.out.println(cveId + " UPDATED (last_update newer)");
                            }



                        } catch (Exception e) {
                            System.err.println("Error saving advisory: " + e.getMessage());
                        }
                    }

                    if (advList.size() < pageSize) break;

                    pageIndex++;

                    Thread.sleep(2200);
                }
                catch (Exception e) {
                    System.err.println("Error fetching Cisco year " + year + " page " + pageIndex);
                    break;
                }
            }
            log.setUpdatedData(updatedThisYear);
            log.setAddedData(addedThisYear);
            log.setTotalData(yearTotalCount);
            log.setVendorName(vendor);
            log.setYear(String.valueOf(year));
            logRepository.save(log);


            System.out.println("Year " + year + " completed. New CVEs added: " + addedThisYear + " Updated Data: " + updatedThisYear );
        }
        // Check if summary record exists
        VendorFetchLog summary = logRepository
                .findByVendorNameAndYear(vendor, "1997 to 2025")
                .orElse(null);

        if (summary == null) {
            // Create new summary only once
            summary = new VendorFetchLog();
            summary.setVendorName(vendor);
            summary.setYear("1997 to 2025");
        }

// Update fields
        summary.setPreviousFetchTime(summary.getLastFetchTime());
        summary.setAddedData(totalAdded);
        summary.setUpdatedData(totalUpdated);
        summary.setLastFetchTime(startTimeall);
        summary.setTotalData((int) advisoryRepository.count());

        logRepository.save(summary);

        System.out.println("ALL YEARS DONE. Total NEW added: " + totalAdded);

    }

    private ResponseEntity<String> safeCiscoRequest(String url, HttpEntity<String> entity) {
        try {
            return restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        }
        catch (HttpClientErrorException e) {

            if (e.getStatusCode().value() == 401 || e.getStatusCode().value() == 403) {

                System.out.println("Token expired → Getting new token...");

                String newToken = getAccessToken();

                HttpHeaders newHeaders = new HttpHeaders();
                newHeaders.set("Authorization", "Bearer " + newToken);
                newHeaders.set("Accept", MediaType.APPLICATION_JSON_VALUE);
                HttpEntity<String> newEntity = new HttpEntity<>(newHeaders);

                return restTemplate.exchange(url, HttpMethod.GET, newEntity, String.class);
            }
            return new ResponseEntity<>(
                    e.getResponseBodyAsString(),
                    e.getStatusCode()
            );
        }
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
            System.err.println("CSAF fetch failed for " + url + ": " + e.getMessage());
            return mapper.createObjectNode();
        }
    }

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

    // software version find for the stored data
    public Map<String, Object> checkProductVersion(String vendor, String product, String version) {
        Map<String, Object> result = new HashMap<>();

        List<CiscoAdvisory> list = advisoryRepository.searchByProduct(product);
        if (list.isEmpty()) {
            result.put("status", "NOT_FOUND");
            result.put("message", "Product not found in advisory database");
            return result;
        }

        boolean foundAdvisory = false;

        for (CiscoAdvisory adv : list) {
            JsonNode notes = adv.getCsaf().path("document").path("notes");

            JsonNode fixedSection = null;
            if (notes.isArray()) {
                for (JsonNode n : notes) {
                    if (n.path("category").asText("").equalsIgnoreCase("general") &&
                            n.path("title").asText("").equalsIgnoreCase("Fixed Software")) {
                        fixedSection = n;
                        break;
                    }
                }
            }

            if (fixedSection == null) continue;

            String rawText = fixedSection.path("text").asText("");
            System.out.println("Raw Fixed Software text:");
            System.out.println(rawText);

            Map<String, String> fixedVersions = extractFixedVersions(rawText);
            System.out.println("Parsed fixed versions: " + fixedVersions);

            if (fixedVersions.isEmpty()) continue;

            foundAdvisory = true;
            String fix = getFixForVersion(fixedVersions, version);

            // If the fix is MIGRATE, suggest the best available fix version
            if ("MIGRATE".equals(fix)) {
                String suggestedFix = suggestBestFixVersion(fixedVersions, version);
                if (!"MIGRATE".equals(suggestedFix)) {
                    result.put("status", "AFFECTED");
                    result.put("fix_version", suggestedFix);
                    result.put("advisory_id", adv.getCisco_data().path("advisory_id").asText());
                    result.put("note", "Original advisory suggests migration, but " + suggestedFix + " is the earliest available fixed version");
                    return result;
                }
            }

            if (fix != null) {
                result.put("status", "AFFECTED");
                result.put("fix_version", fix);
                result.put("advisory_id", adv.getCisco_data().path("advisory_id").asText());
                return result;
            }
        }

        if (foundAdvisory) {
            result.put("status", "NOT_AFFECTED");
        } else {
            result.put("status", "NO_ADVISORY_DATA");
            result.put("message", "No fixed software information found in advisories");
        }

        return result;
    }
    private Map<String, String> extractFixedVersions(String text) {
        Map<String, String> map = new HashMap<>();

        if (text == null || text.isEmpty()) {
            return map;
        }

        // Clean and normalize the text
        text = text.replaceAll("\\r\\n", "\n").trim();

        // Look for version-fix pairs in the text
        String[] lines = text.split("\n");

        for (String line : lines) {
            line = line.trim();

            // Skip header lines and very long lines
            if (line.contains("First Fixed Release") ||
                    line.contains("Fixed Release") ||
                    line.contains("Release") && line.contains("Fixed") ||
                    line.length() > 200) {
                continue;
            }

            // Pattern for version and fix pairs
            // Matches: "23.0  Migrate to a fixed release." or "24.0  24.0.2025.05"
            Pattern pattern = Pattern.compile("^(\\d+(?:\\.\\d+)*|Earlier\\s+than\\s+[\\w\\.]+)\\s+(Migrate(?:\\.)?|([\\w\\.]+(?:\\.[\\w\\.]+)*))", Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(line);

            if (matcher.find()) {
                String version = matcher.group(1).trim();
                String fix = matcher.group(2).trim();

                // Handle "Earlier than X" cases
                if (version.toLowerCase().startsWith("earlier than")) {
                    version = "earlier";
                }

                if (fix.toLowerCase().contains("migrate")) {
                    map.put(version, "MIGRATE");
                } else {
                    // Clean the fix version - take only the version part before any spaces
                    String cleanFix = fix.split("\\s+")[0];
                    map.put(version, cleanFix);
                }
                System.out.println("Parsed: " + version + " -> " + map.get(version));
            }

            // Also try to match simple version-version pairs without "Migrate"
            Pattern simplePattern = Pattern.compile("^(\\d+(?:\\.\\d+)+)\\s+(\\d+(?:\\.\\d+)+(?:\\.[\\w\\.]+)*)");
            Matcher simpleMatcher = simplePattern.matcher(line);
            if (simpleMatcher.find()) {
                String version = simpleMatcher.group(1).trim();
                String fix = simpleMatcher.group(2).trim();
                map.put(version, fix);
                System.out.println("Simple parsed: " + version + " -> " + fix);
            }
        }

        return map;
    }

    private Map<String, String> parseStructuredTable(String text) {
        Map<String, String> map = new HashMap<>();

        // Split into lines and look for table structure
        String[] lines = text.split("\n");
        List<String> tableLines = new ArrayList<>();
        boolean inTable = false;

        for (String line : lines) {
            line = line.trim();

            // Detect table start
            if (line.matches(".*(First Fixed Release|Fixed Release|Fixed Version).*") ||
                    line.matches(".*Release.*Fixed.*") ||
                    (line.contains("Migrate") && line.length() < 100) ||
                    (line.matches(".*\\d+.*") && line.matches(".*(Migrate|\\d+\\.\\d+).*") && line.length() < 150)) {
                inTable = true;
            }

            // Detect table end
            if (line.contains("Cisco Product Security") ||
                    line.contains("PSIRT validates") ||
                    line.contains("https://") ||
                    line.length() > 200) {
                inTable = false;
            }

            if (inTable && !line.isEmpty()) {
                tableLines.add(line);
            }
        }

        // Parse table lines
        for (String line : tableLines) {
            // Remove multiple spaces and clean the line
            line = line.replaceAll("\\s+", " ").trim();

            // Pattern for: "11 11.32.2.1" or "9 Migrate to a fixed release"
            Pattern pattern = Pattern.compile("^(\\d+(?:\\.\\d+)*|Earlier(?:\\s+than\\s+\\d+(?:\\.\\d+)*)?)\\s+(Migrate(?:\\s+to\\s+a\\s+fixed\\s+release)?|\\(?\\d+(?:\\.\\d+)+\\)?[^\\s]*)(?:\\s|$)");
            Matcher matcher = pattern.matcher(line);

            if (matcher.find()) {
                String version = matcher.group(1).trim();
                String fixed = matcher.group(2).trim();

                if (fixed.toLowerCase().contains("migrate")) {
                    map.put(version, "MIGRATE");
                } else {
                    // Clean up the fixed version - remove parentheses and extra text
                    String cleanFixed = fixed.replaceAll("[\\(\\)]", "").split("\\s+")[0];
                    map.put(version, cleanFixed);
                }
            }

            // Also try to match common Cisco table formats with multiple columns
            String[] parts = line.split("\\s{2,}|\\t");
            if (parts.length >= 2) {
                String version = parts[0].trim();
                String fixed = parts[1].trim();

                if (isValidVersion(version) && (isValidVersion(fixed) || fixed.toLowerCase().contains("migrate"))) {
                    if (fixed.toLowerCase().contains("migrate")) {
                        map.put(version, "MIGRATE");
                    } else {
                        map.put(version, fixed.split("\\s+")[0]);
                    }
                }
            }
        }

        return map;
    }

    private Map<String, String> parseSimpleVersionPairs(String text) {
        Map<String, String> map = new HashMap<>();

        // Pattern for simple version-fix pairs
        Pattern pattern = Pattern.compile("(\\d+(?:\\.\\d+)*|Earlier)\\s+([A-Z][a-z]+\\s+[^\\s]+|\\d+(?:\\.\\d+)+[^\\s]*|Migrate[^\\s]*)");
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            String version = matcher.group(1).trim();
            String fixed = matcher.group(2).trim();

            if (fixed.toLowerCase().contains("migrate")) {
                map.put(version, "MIGRATE");
            } else {
                // Extract just the version part
                String cleanFixed = extractVersionNumber(fixed);
                if (cleanFixed != null) {
                    map.put(version, cleanFixed);
                }
            }
        }

        return map;
    }

    private Map<String, String> parseCiscoPatterns(String text) {
        Map<String, String> map = new HashMap<>();

        // Common Cisco patterns
        String[] patterns = {
                "(\\d+(?:\\.\\d+)*)\\s+(\\d+(?:\\.\\d+)+(?:SR\\d+)?(?:[^\\s.]*))",
                "Earlier than (\\d+(?:\\.\\d+)*)\\s+Migrate",
                "(\\d+(?:\\.\\d+)*\\.?\\d*)\\s+(\\d+(?:\\.\\d+)+(?:[^\\s.]*))"
        };

        for (String patternStr : patterns) {
            Pattern pattern = Pattern.compile(patternStr);
            Matcher matcher = pattern.matcher(text);

            while (matcher.find()) {
                if (matcher.groupCount() >= 2) {
                    String version = matcher.group(1).trim();
                    String fixed = matcher.group(2).trim();

                    if (fixed.toLowerCase().contains("migrate")) {
                        map.put(version, "MIGRATE");
                    } else {
                        String cleanFixed = extractVersionNumber(fixed);
                        if (cleanFixed != null) {
                            map.put(version, cleanFixed);
                        }
                    }
                }
            }
        }

        return map;
    }

    private boolean isValidVersion(String version) {
        return version != null &&
                (version.matches("\\d+(\\.\\d+)*") ||
                        version.equalsIgnoreCase("earlier") ||
                        version.toLowerCase().contains("migrate"));
    }

    private String extractVersionNumber(String text) {
        if (text == null) return null;

        // Look for version patterns like: 11.32.2.1, 3.3(1), 14.3(1)SR2, etc.
        Pattern pattern = Pattern.compile("(\\d+(?:\\.\\d+)+(?:\\(\\d+\\))?(?:SR\\d+)?(?:[^\\s.]*))");
        Matcher matcher = pattern.matcher(text);

        if (matcher.find()) {
            return matcher.group(1).trim();
        }

        return null;
    }

    private String getFixForVersion(Map<String, String> table, String version) {
        System.out.println("Checking version: " + version + " against table: " + table);

        // Direct match
        if (table.containsKey(version)) {
            String fix = table.get(version);
            System.out.println("Direct match found: " + fix);
            return fix;
        }

        List<Integer> current = normalize(version);
        List<String> allKeys = new ArrayList<>(table.keySet());

        // Sort all versions in ascending order
        allKeys.sort((a, b) -> compareVersion(normalize(a), normalize(b)));

        System.out.println("All sorted versions: " + allKeys);

        // Find the position of our current version in the sorted list
        int currentIndex = -1;
        for (int i = 0; i < allKeys.size(); i++) {
            List<Integer> candidate = normalize(allKeys.get(i));
            if (compareVersion(current, candidate) == 0) {
                currentIndex = i;
                break;
            } else if (compareVersion(current, candidate) < 0) {
                // Current version is between previous and this one
                currentIndex = i - 1;
                break;
            }
        }

        // If we didn't find a position, current version is after all listed versions
        if (currentIndex == -1) {
            currentIndex = allKeys.size() - 1;
        }

        System.out.println("Current version position index: " + currentIndex);

        // Look for the next available FIXED version (not MIGRATE)
        for (int i = currentIndex; i < allKeys.size(); i++) {
            String key = allKeys.get(i);
            String fix = table.get(key);

            if (!"MIGRATE".equals(fix)) {
                System.out.println("Found actual fix version: " + fix + " for key: " + key);
                return fix;
            }
        }

        // If no fixed version found, return MIGRATE from current position
        String currentKey = currentIndex >= 0 && currentIndex < allKeys.size() ? allKeys.get(currentIndex) : null;
        if (currentKey != null && table.containsKey(currentKey)) {
            String migrateFix = table.get(currentKey);
            System.out.println("No specific fix found, returning: " + migrateFix);
            return migrateFix;
        }

        // Final fallback
        System.out.println("No fix version found");
        return "MIGRATE";
    }

    private List<Integer> normalize(String v) {
        List<Integer> list = new ArrayList<>();
        for (String part : v.split("[^0-9]+")) {
            if (!part.isBlank()) {
                try {
                    list.add(Integer.parseInt(part));
                } catch (NumberFormatException ignored) {}
            }
        }
        return list;
    }


    private int compareVersion(List<Integer> v1, List<Integer> v2) {
        int len = Math.max(v1.size(), v2.size());

        for (int i = 0; i < len; i++) {
            int a = (i < v1.size()) ? v1.get(i) : 0;
            int b = (i < v2.size()) ? v2.get(i) : 0;

            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        return 0;
    }



    private String suggestBestFixVersion(Map<String, String> table, String currentVersion) {
        System.out.println("Looking for best available fix for: " + currentVersion);

        List<String> availableFixes = new ArrayList<>();
        for (Map.Entry<String, String> entry : table.entrySet()) {
            if (!"MIGRATE".equals(entry.getValue()) && !entry.getKey().equals("earlier")) {
                availableFixes.add(entry.getValue());
            }
        }

        if (!availableFixes.isEmpty()) {
            // Sort available fixes and return the lowest one
            availableFixes.sort((a, b) -> compareVersion(normalize(a), normalize(b)));
            String bestFix = availableFixes.get(0);
            System.out.println("Suggested best available fix: " + bestFix);
            return bestFix;
        }

        return "MIGRATE";
    }


    public JsonNode fetchLatestByProduct(String product , String versionnum) throws Exception {
        String osType = extractOsType(product);
        String version = versionnum;
        CiscoAdvisory findData = advisoryRepository.findLatestByProduct(osType, versionnum);




        String url = "https://apix.cisco.com/security/advisories/v2/OSType/"
                + osType
                + "?version=" + version;

        if (findData != null) {
            JsonNode ciscoDataJson = mapper.readTree(findData.getCisco_data().toString());

            // Try both advisoryId & advisory_id
            String advisoryId = ciscoDataJson.path("advisoryId").asText();
            if (advisoryId.isEmpty()) {
                advisoryId = ciscoDataJson.path("advisory_id").asText();
            }

            if (!advisoryId.isEmpty()) {
                url = url + "&advisoryId=" + advisoryId;
                System.out.println("advisoryId added = " + advisoryId);
            } else {
                System.out.println("advisoryId NOT FOUND in DB JSON");
            }
        }

        if (findData == null) {
            System.out.println("Product NOT FOUND in DB JSON");

        }
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + getAccessToken());
        headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        System.out.println("full url" + url);
        ResponseEntity<String> response = safeCiscoRequest(url, new HttpEntity<>(headers));

        JsonNode result = mapper.readTree(response.getBody());

        // Treat invalid version or no data as NOT_AFFECTED
        if (result.has("errorCode")) {
            String errorCode = result.path("errorCode").asText().toUpperCase();

            // Handle invalid versions
            if (errorCode.contains("INVALID")) {
                ObjectNode resp = mapper.createObjectNode();
                resp.put("product", product);
                resp.put("version", version);
                resp.put("status", "Invalid"); // or "AFFECTED" if desired
                resp.put("message", "Product not found in database table");
                return resp;
            }

            // Handle valid but not affected versions
            if ("NO_DATA_FOUND".equals(errorCode)) {
                ObjectNode resp = mapper.createObjectNode();
                resp.put("product", product);
                resp.put("version", version);
                resp.put("status", "NOT_AFFECTED");
                resp.put("message", "Version exists but not affected");
                return resp;
            }
        }

// If neither INVALID nor NO_DATA_FOUND, extract advisories normally
        JsonNode advisories = result.path("advisories");

        JsonNode advisoryNode = advisories.get(0);

        String lastUpdatedDate = advisoryNode.path("lastUpdated").asText("");
        if (!isEligible(osType, lastUpdatedDate)) {
            ObjectNode resp = mapper.createObjectNode();
            resp.put("product", product);
            resp.put("version", version);
            resp.put("status", "Old data not allowed");
            resp.put("message", "Advisory is older than allowed minimum date");
            return resp;
        }
        String fixedVersion = "Contact your support organization for upgrade instructions.";


        JsonNode firstFixed = advisoryNode.path("firstFixed");
        if (firstFixed.isArray() && firstFixed.size() > 0) {
            fixedVersion = firstFixed.get(0).asText();
        }

        if (fixedVersion.startsWith("Contact")) {
            JsonNode platforms = advisoryNode.path("platforms");
            if (platforms.isArray()) {
                for (JsonNode platform : platforms) {
                    JsonNode firstFixes = platform.path("firstFixes");

                    if (firstFixes.isArray() && firstFixes.size() > 0) {
                        JsonNode fixNode = firstFixes.get(0);
                        if (fixNode.has("name")) {
                            fixedVersion = fixNode.get("name").asText();
                            break; // take first found
                        }
                    }
                }
            }
        }

        ObjectNode resp = mapper.createObjectNode();
        resp.put("product", product);
        resp.put("currentAffectedVersion", version);
        resp.put("fixedVersion", fixedVersion);
        resp.put("cveId", advisoryNode.path("cves").get(0).asText(""));
        resp.put("advisoryId", advisoryNode.path("advisoryId").asText(""));
        resp.put("advisoryTitle", advisoryNode.path("advisoryTitle").asText(""));
        resp.put("cvssBaseScore", advisoryNode.path("cvssBaseScore").asText(""));
        resp.put("status", advisoryNode.path("status").asText(""));
        resp.put("sir", advisoryNode.path("sir").asText(""));
        resp.put("lastUpdated", advisoryNode.path("lastUpdated").asText(""));
        resp.put("firstPublished", advisoryNode.path("firstPublished").asText(""));
        resp.put("summary", advisoryNode.path("summary").asText(""));

        return resp;
    }





        private boolean isEligible(String osType, String lastUpdatedDate) {

        LocalDate minDate;

        switch (osType) {
            case "asa":
            case "fmc":
            case "ftd":
            case "fxos":
                minDate = LocalDate.of(2022, 1, 1);
                break;

            case "nxos":
            case "aci":
                minDate = LocalDate.of(2019, 7, 1);
                break;

            default:
                // ios / iosxe always allowed
                return true;
        }

        LocalDate advisoryDate = LocalDate.parse(lastUpdatedDate.substring(0, 10));

        return advisoryDate.isEqual(minDate) || advisoryDate.isAfter(minDate);
    }

    private String extractOsType(String product) {
        product = product.toLowerCase();

        if (product.contains("ios xe")) return "iosxe";
        if (product.contains("ios")) return "ios";
        if (product.contains("nx-os") || product.contains("nxos")) return "nxos";
        if (product.contains("asa")) return "asa";
        if (product.contains("ftd")) return "ftd";
        if (product.contains("fxos")) return "fxos";
        if (product.contains("fmc")) return "fmc";
        if (product.contains("aci")) return "aci";

        return product; // default fallback
    }

    private String extractVersion(String product) {
        Pattern p = Pattern.compile("(\\d+(\\.\\d+)*([A-Za-z0-9().-]+)?)");
        Matcher m = p.matcher(product);

        String lastMatch = "";
        while (m.find()) {
            lastMatch = m.group();
        }
        return lastMatch;
    }


}






