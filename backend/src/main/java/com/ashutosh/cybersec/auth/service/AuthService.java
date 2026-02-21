package com.ashutosh.cybersec.auth.service;

import com.ashutosh.cybersec.auth.dto.RegisterRequest;
import com.ashutosh.cybersec.auth.entity.User;
import com.ashutosh.cybersec.auth.repository.UserRepository;
import com.ashutosh.cybersec.detection.service.DetectionService;
import com.ashutosh.cybersec.logs.service.LogService;
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
    private final LogService logService;
    private final DetectionService detectionService;

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

    public String login(String username, String password, String ipAddress) {

        // 1️⃣ Check brute-force block in Redis
        if (loginAttemptService.isBlocked(username)) {
            logService.save(username, "ACCOUNT_BLOCKED", ipAddress);
            throw new RuntimeException("Too many failed attempts. Try again later.");
        }

        // 2️⃣ Fetch user from MySQL
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        // 3️⃣ Wrong password
        if (!passwordEncoder.matches(password, user.getPassword())) {

            loginAttemptService.loginFailed(username);          // Redis counter
            logService.save(username, "FAILED_LOGIN", ipAddress); // DB audit log
            detectionService.checkBruteForce(username);
            detectionService.checkCredentialStuffing(ipAddress);

            throw new RuntimeException("Invalid username or password");
        }

        // 4️⃣ Successful login
        loginAttemptService.loginSucceeded(username);             // reset Redis
        logService.save(username, "LOGIN_SUCCESS", ipAddress);    // DB audit log
        detectionService.checkSuspiciousLogin(username);
        // 5️⃣ Generate JWT using username (IMPORTANT)
        return jwtService.generateToken(user.getUsername());
    }

}

