package com.example.jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/public")
    public Map<String, String> publicAccess() {
        return Map.of(
                "status", "success",
                "message", "Public Content. Anyone is welcome without authentication!"
        );
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public Map<String, String> userAccess() {
        return Map.of(
                "status", "success",
                "message", "User Content. Accessible by USER and ADMIN roles."
        );
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> adminAccess() {
        return Map.of(
                "status", "success",
                "message", "Admin Content. ONLY accessible by users with ADMIN role!"
        );
    }
}
