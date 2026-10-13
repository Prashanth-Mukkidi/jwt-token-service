package com.example.jwt;

import com.example.jwt.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class JwtTokenGeneratorApplicationTests {

	@Autowired
	private JwtUtil jwtUtil;

	@Test
	void contextLoads() {
		assertNotNull(jwtUtil);
	}

	@Test
	void testGenerateAndValidateToken() {
		String username = "testuser";
		String token = jwtUtil.generateToken(username);

		assertNotNull(token);
		assertFalse(token.isBlank());

		// Extract username
		String extractedUsername = jwtUtil.extractUsername(token);
		assertEquals(username, extractedUsername);

		// Validate token
		assertTrue(jwtUtil.validateToken(token, username));
		assertFalse(jwtUtil.isTokenExpired(token));
	}

	@Test
	void testTokenWithCustomClaims() {
		String username = "alice";
		Map<String, Object> claims = Map.of("role", "ROLE_ADMIN", "department", "Engineering");
		String token = jwtUtil.generateToken(username, claims);

		assertNotNull(token);
		assertEquals(username, jwtUtil.extractUsername(token));

		var extractedClaims = jwtUtil.extractAllClaims(token);
		assertEquals("ROLE_ADMIN", extractedClaims.get("role"));
		assertEquals("Engineering", extractedClaims.get("department"));
	}
}
