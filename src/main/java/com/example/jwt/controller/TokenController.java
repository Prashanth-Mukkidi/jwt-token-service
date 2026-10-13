package com.example.jwt.controller;

import com.example.jwt.dto.GenerateTokenRequest;
import com.example.jwt.dto.TokenInfoResponse;
import com.example.jwt.dto.TokenValidationRequest;
import com.example.jwt.security.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/token")
public class TokenController {

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Directly generate a JWT token with custom claims, roles, or custom expiration time.
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generateToken(@RequestBody GenerateTokenRequest request) {
        if (request.getUsername() == null || request.getUsername().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username is required to generate a token"));
        }

        Map<String, Object> claims = new HashMap<>();
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            claims.put("roles", request.getRoles());
        }
        if (request.getCustomClaims() != null) {
            claims.putAll(request.getCustomClaims());
        }

        long expiration = request.getExpirationMillis() != null && request.getExpirationMillis() > 0
                ? request.getExpirationMillis()
                : jwtUtil.getJwtExpiration();

        String token = jwtUtil.generateToken(request.getUsername(), claims, expiration);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "tokenType", "Bearer",
                "username", request.getUsername(),
                "expiresIn", expiration,
                "claims", claims,
                "issuedAt", new Date(),
                "expiresAt", new Date(System.currentTimeMillis() + expiration)
        ));
    }

    /**
     * Validate an existing JWT token and check expiration or matching username.
     */
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestBody TokenValidationRequest request) {
        String token = request.getToken();
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Token is required for validation"));
        }

        // Clean bearer prefix if accidentally included
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        boolean isValid;
        if (request.getUsername() != null && !request.getUsername().isBlank()) {
            isValid = jwtUtil.validateToken(token, request.getUsername());
        } else {
            isValid = jwtUtil.validateToken(token);
        }

        return ResponseEntity.ok(Map.of(
                "valid", isValid,
                "message", isValid ? "Token is valid and active" : "Token is invalid, expired, or corrupted"
        ));
    }

    /**
     * Inspect and parse JWT claims, issuance date, and expiration.
     */
    @PostMapping("/parse")
    public ResponseEntity<?> parseToken(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Token is required to parse"));
        }

        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        try {
            Claims claims = jwtUtil.extractAllClaims(token);
            boolean isExpired = jwtUtil.isTokenExpired(token);

            TokenInfoResponse response = TokenInfoResponse.builder()
                    .valid(true)
                    .subject(claims.getSubject())
                    .issuedAt(claims.getIssuedAt())
                    .expiresAt(claims.getExpiration())
                    .expired(isExpired)
                    .claims(claims)
                    .message(isExpired ? "Token signature is valid but token has expired" : "Token is valid")
                    .build();

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(
                    TokenInfoResponse.builder()
                            .valid(false)
                            .message("Failed to parse token: " + e.getMessage())
                            .build()
            );
        }
    }
}
