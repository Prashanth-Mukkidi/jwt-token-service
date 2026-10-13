package com.example.jwt;

import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class JwtTokenGeneratorApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtTokenGeneratorApplication.class, args);
    }

    /**
     * Seeds initial demo users for quick testing if database is empty.
     */
    @Bean
    public CommandLineRunner initDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.count() == 0) {
                // Regular User
                User normalUser = new User();
                normalUser.setUsername("user");
                normalUser.setPassword(passwordEncoder.encode("user123"));
                normalUser.setRoles(Set.of("ROLE_USER"));
                userRepository.save(normalUser);

                // Admin User
                User adminUser = new User();
                adminUser.setUsername("admin");
                adminUser.setPassword(passwordEncoder.encode("admin123"));
                adminUser.setRoles(Set.of("ROLE_ADMIN", "ROLE_USER"));
                userRepository.save(adminUser);

                System.out.println("==================================================");
                System.out.println("Demo users seeded successfully:");
                System.out.println(" - Normal User -> username: user, password: user123 (ROLE_USER)");
                System.out.println(" - Admin User  -> username: admin, password: admin123 (ROLE_ADMIN, ROLE_USER)");
                System.out.println("==================================================");
            }
        };
    }
}
