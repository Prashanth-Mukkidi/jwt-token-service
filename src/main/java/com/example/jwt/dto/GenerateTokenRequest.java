package com.example.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GenerateTokenRequest {
    private String username;
    private List<String> roles;
    private Map<String, Object> customClaims;
    private Long expirationMillis; // optional override for token lifetime
}
