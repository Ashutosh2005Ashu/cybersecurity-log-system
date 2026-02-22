package com.ashutosh.cybersec.detection.service;

import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.detection.repository.DetectionAlertRepository;
import com.ashutosh.cybersec.detection.rules.*;
import com.ashutosh.cybersec.logs.entity.Log;
import com.ashutosh.cybersec.logs.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class DetectionService {

    private final DetectionAlertRepository alertRepository;
    private final LogRepository logRepository;

    private final BruteForceRule bruteForceRule;
    private final CredentialStuffingRule credentialStuffingRule;
    private final SuspiciousLoginRule suspiciousLoginRule;
    private final DosRule dosRule;

    // 🔹 COMMON DEDUP METHOD
    private boolean isNewAlert(String identifier, String type) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        return !alertRepository.existsByUsernameAndTypeAndCreatedAtAfter(
                identifier,
                type,
                windowStart
        );
    }

    // 🔴 1. BRUTE FORCE
    public void checkBruteForce(String username) {

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> logs = logRepository
                .findByUsernameAndActionAndTimestampAfter(
                        username,
                        "FAILED_LOGIN",
                        windowStart
                );

        if (bruteForceRule.isTriggered(logs)
                && isNewAlert(username, "BRUTE_FORCE")) {

            DetectionAlert alert = DetectionAlert.builder()
                    .username(username)
                    .type("BRUTE_FORCE")
                    .message("Multiple failed login attempts within 5 minutes")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
        }
    }

    // 🔴 2. CREDENTIAL STUFFING
    public void checkCredentialStuffing(String ipAddress) {

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> logs = logRepository
                .findByIpAddressAndActionAndTimestampAfter(
                        ipAddress,
                        "FAILED_LOGIN",
                        windowStart
                );

        if (credentialStuffingRule.isTriggered(logs)
                && isNewAlert(ipAddress, "CREDENTIAL_STUFFING")) {

            DetectionAlert alert = DetectionAlert.builder()
                    .username(ipAddress) // storing IP here
                    .type("CREDENTIAL_STUFFING")
                    .message("Multiple login failures from same IP across users")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
        }
    }

    // 🔴 3. SUSPICIOUS LOGIN
    public void checkSuspiciousLogin(String username) {

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> logs = logRepository
                .findByUsernameAndActionAndTimestampAfter(
                        username,
                        "LOGIN_SUCCESS",
                        windowStart
                );

        if (suspiciousLoginRule.isTriggered(logs)
                && isNewAlert(username, "SUSPICIOUS_LOGIN")) {

            DetectionAlert alert = DetectionAlert.builder()
                    .username(username)
                    .type("SUSPICIOUS_LOGIN")
                    .message("Login from multiple IPs in short time")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
        }
    }

    // 🔴 4. DOS ATTACK
    public void checkDos(String ipAddress) {

        List<Log> logs = logRepository.findByIpAddress(ipAddress);

        if (dosRule.isTriggered(logs)
                && isNewAlert(ipAddress, "DOS_ATTACK")) {

            DetectionAlert alert = DetectionAlert.builder()
                    .username(ipAddress) // storing IP
                    .type("DOS_ATTACK")
                    .message("High number of requests from same IP")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
        }
    }
}