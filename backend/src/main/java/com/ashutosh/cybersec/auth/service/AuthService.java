package com.ashutosh.cybersec.auth.service;

import com.ashutosh.cybersec.auth.dto.RegisterRequest;
import com.ashutosh.cybersec.auth.entity.User;
import com.ashutosh.cybersec.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.ashutosh.cybersec.common.enums.Role;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final LoginAttemptService loginAttemptService;

    public String register(RegisterRequest request) {

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() == null ? Role.USER : request.getRole())
                .build();

        userRepository.save(user);
        return "User registered successfully";
    }

    public String login(String username, String password) {

        // 🔒 Check brute-force lock FIRST
        if (loginAttemptService.isBlocked(username)) {
            throw new RuntimeException(
                    "Too many failed attempts. Try again later."
            );
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new RuntimeException("Invalid username or password")
                );

        // Wrong password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            loginAttemptService.loginFailed(username);
            throw new RuntimeException("Invalid username or password");
        }

        // Successful login → reset attempts
        loginAttemptService.loginSucceeded(username);

        return jwtService.generateToken(user.getUsername());
    }
}

