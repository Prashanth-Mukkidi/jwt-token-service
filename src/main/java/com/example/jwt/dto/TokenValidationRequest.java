package com.example.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationRequest {
    private String token;
    private String username; // optional: validate if token belongs to specific username
}
