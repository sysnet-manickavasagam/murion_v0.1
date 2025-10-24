//package com.example.murion.v10.Service;
//
//import jakarta.annotation.PostConstruct;
//import org.springframework.stereotype.Service;
//
//@Service
//public class TokenService {
//
//    private static String ciscoToken;
//
//    // Updated default token - make sure this is your actual valid token
//    private static final String DEFAULT_TOKEN = "eyJraWQiOiJqNHJGLWx1WW5jRjF1d0VQU01OVDd5OHV2Q1NDMGRXM2xRSFJra3QxM3JBIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULk5DTXoxRW9EamlsV2pLMkI3Q1pobi1wYWNmYlhPeFJFQzgzeHhXSjRRMk0iLCJpc3MiOiJodHRwczovL2lkLmNpc2NvLmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE3NjExMzU0NzcsImV4cCI6MTc2MTEzOTA3NywiY2lkIjoicTM3d3U1Z2EzNjk1cjNqZnpjY25mcDhxIiwic2NwIjpbImN1c3RvbXNjb3BlIl0sInN1YiI6InEzN3d1NWdhMzY5NXIzamZ6Y2NuZnA4cSIsImF6cCI6InEzN3d1NWdhMzY5NXIzamZ6Y2NuZnA4cSJ9.Lmd-Riz9XT_dGzIrZedyKN9P3RGapXgHa3Eg_lMihZzMTgAD9UYBfb_cVcva4RBSVoKs0hsNU20INwFZJsqh4WhxMab-arQG_CCL0Maee4FTnMuxu-pHND3mFHsXD8S_IAhYMfszAgKS3usrAgX3EhQH5DfRSax18UuqoUDkoPWM8oo7hycUP74PxXasOyj6bdGEwLAcgP9b0_llo90LpUvrNkAJuSazRfz51nHItEcuv-tOMvpn-9srjf7Tj12owX0RcO5J2gixB_jYC19B-Ffgw3hdYu_ZxhHtyzvegN1TANbj1q2oDxKRR5ijmQdyPdEbbgbFaQUk6LUR0QDa1Q";
//
//    @PostConstruct
//    public void init() {
//        // Initialize with default token
//        ciscoToken = DEFAULT_TOKEN;
//        System.out.println("🔑 Token Service Initialized");
//        System.out.println("📝 Current Token: " + (ciscoToken != null ?
//                ciscoToken.substring(0, Math.min(20, ciscoToken.length())) + "..." : "NULL"));
//
//        // Validate token format
//        if (isTokenValid()) {
//            System.out.println("✅ Token is configured and valid");
//        } else {
//            System.out.println("❌ Token is not properly configured");
//        }
//    }
//
//    public static String getCiscoToken() {
//        if (!isTokenValid()) {
//            throw new IllegalStateException("❌ Cisco API token not configured. Please update the token in TokenService.java");
//        }
//        return ciscoToken;
//    }
//
//    public static void setCiscoToken(String newToken) {
//        if (newToken == null || newToken.trim().isEmpty()) {
//            throw new IllegalArgumentException("Token cannot be null or empty");
//        }
//        ciscoToken = newToken.trim();
//        System.out.println("✅ Token updated successfully!");
//        System.out.println("📝 New Token: " + ciscoToken.substring(0, Math.min(20, ciscoToken.length())) + "...");
//    }
//
//    public static boolean isTokenValid() {
//        return ciscoToken != null &&
//                !ciscoToken.trim().isEmpty() &&
//                !ciscoToken.equals("YOUR_NEW_TOKEN_HERE") &&
//                ciscoToken.startsWith("eyJ"); // Basic JWT token format check
//    }
//}