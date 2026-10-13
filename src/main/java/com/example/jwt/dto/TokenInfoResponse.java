package com.example.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenInfoResponse {
    private boolean valid;
    private String subject;
    private Date issuedAt;
    private Date expiresAt;
    private boolean expired;
    private Map<String, Object> claims;
    private String message;
}
