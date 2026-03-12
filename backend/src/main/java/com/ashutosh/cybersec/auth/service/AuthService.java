package com.ashutosh.cybersec.auth.service;

import com.ashutosh.cybersec.auth.dto.RegisterRequest;
import com.ashutosh.cybersec.auth.entity.User;
import com.ashutosh.cybersec.auth.repository.UserRepository;
import com.ashutosh.cybersec.common.enums.Role;
import com.ashutosh.cybersec.common.exception.DuplicateResourceException;
import com.ashutosh.cybersec.common.exception.InvalidCredentialsException;
import com.ashutosh.cybersec.common.exception.UserBlockedException;
import com.ashutosh.cybersec.detection.service.DetectionService;
import com.ashutosh.cybersec.logs.service.LogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final LoginAttemptService loginAttemptService;
    private final LogService logService;
    private final DetectionService detectionService;

    @Transactional
    public String register(RegisterRequest request) {

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new DuplicateResourceException("Username already exists");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new DuplicateResourceException("Email already exists");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() == null ? Role.USER : request.getRole())
                .build();

        userRepository.save(user);
        log.info("User registered: {}", request.getUsername());
        return "User registered successfully";
    }


    public String login(String username, String password, String ipAddress) {
        // 1️⃣ Check brute-force block in Redis
        if (loginAttemptService.isBlocked(username)) {
            logService.save(username, "ACCOUNT_BLOCKED", ipAddress);
            log.warn("Blocked login attempt for user: {} from IP: {}", username, ipAddress);
            throw new UserBlockedException("Too many failed attempts. Try again later.");
        }

        // 2️⃣ Fetch user from MySQL
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    logService.save(username, "FAILED_LOGIN", ipAddress);
                    return new InvalidCredentialsException("Invalid username or password");
                });

        // 3️⃣ Wrong password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            loginAttemptService.loginFailed(username);              // Redis counter
            logService.save(username, "FAILED_LOGIN", ipAddress);  // DB audit log
            detectionService.checkBruteForce(username);
            detectionService.checkCredentialStuffing(ipAddress);
            detectionService.checkDos(ipAddress);

            throw new InvalidCredentialsException("Invalid username or password");
        }

        // 4️⃣ Successful login
        loginAttemptService.loginSucceeded(username);              // reset Redis
        logService.save(username, "LOGIN_SUCCESS", ipAddress);     // DB audit log
        detectionService.checkSuspiciousLogin(username);
        detectionService.checkDos(ipAddress);

        log.info("Successful login: {} from IP: {}", username, ipAddress);
        // 5️⃣ Generate JWT
        return jwtService.generateToken(user.getUsername());
    }

}

