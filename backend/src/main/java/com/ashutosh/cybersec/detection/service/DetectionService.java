package com.ashutosh.cybersec.detection.service;

import com.ashutosh.cybersec.common.enums.Severity;
import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.detection.repository.DetectionAlertRepository;
import com.ashutosh.cybersec.detection.rules.*;
import com.ashutosh.cybersec.logs.entity.Log;
import com.ashutosh.cybersec.logs.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class DetectionService {

    private final DetectionAlertRepository alertRepository;
    private final LogRepository logRepository;

    private final BruteForceRule bruteForceRule;
    private final CredentialStuffingRule credentialStuffingRule;
    private final SuspiciousLoginRule suspiciousLoginRule;
    private final DosRule dosRule;

    // ── COMMON DEDUP METHOD ──────────────────────────────────────────
    private boolean isNewAlert(String identifier, String type) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);
        return !alertRepository.existsByUsernameAndTypeAndCreatedAtAfter(
                identifier, type, windowStart
        );
    }

    // ── 1. BRUTE FORCE ──────────────────────────────────────────────
    @Transactional
    public void checkBruteForce(String username, String ipAddress) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> logs = logRepository
                .findByUsernameAndActionAndTimestampAfter(username, "FAILED_LOGIN", windowStart);

        if (bruteForceRule.isTriggered(logs) && isNewAlert(username, "BRUTE_FORCE")) {
            DetectionAlert alert = DetectionAlert.builder()
                    .username(username)
                    .ipAddress(ipAddress)
                    .type("BRUTE_FORCE")
                    .severity(Severity.HIGH)
                    .message("Multiple failed login attempts within 5 minutes")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
            log.warn("🚨 BRUTE_FORCE detected for user: {}", username);
        }
    }

    // ── 2. CREDENTIAL STUFFING ──────────────────────────────────────
    @Transactional
    public void checkCredentialStuffing(String ipAddress) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> logs = logRepository
                .findByIpAddressAndActionAndTimestampAfter(ipAddress, "FAILED_LOGIN", windowStart);

        if (credentialStuffingRule.isTriggered(logs) && isNewAlert(ipAddress, "CREDENTIAL_STUFFING")) {
            DetectionAlert alert = DetectionAlert.builder()
                    .ipAddress(ipAddress)
                    .username(ipAddress) // kept for dedup compatibility
                    .type("CREDENTIAL_STUFFING")
                    .severity(Severity.CRITICAL)
                    .message("Multiple login failures from same IP across users")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
            log.warn("🚨 CREDENTIAL_STUFFING detected from IP: {}", ipAddress);
        }
    }

    // ── 3. SUSPICIOUS LOGIN ─────────────────────────────────────────
    @Transactional
    public void checkSuspiciousLogin(String username, String ipAddress) {
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> logs = logRepository
                .findByUsernameAndActionAndTimestampAfter(username, "LOGIN_SUCCESS", windowStart);

        if (suspiciousLoginRule.isTriggered(logs) && isNewAlert(username, "SUSPICIOUS_LOGIN")) {
            DetectionAlert alert = DetectionAlert.builder()
                    .username(username)
                    .ipAddress(ipAddress)
                    .type("SUSPICIOUS_LOGIN")
                    .severity(Severity.MEDIUM)
                    .message("Login from multiple IPs in short time")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
            log.warn("🚨 SUSPICIOUS_LOGIN detected for user: {}", username);
        }
    }

    // ── 4. DOS ATTACK ───────────────────────────────────────────────
    @Transactional
    public void checkDos(String ipAddress) {
        // Use time-windowed query instead of loading ALL logs for this IP
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(1);
        List<Log> logs = logRepository.findByIpAddressAndTimestampAfter(ipAddress, windowStart);

        if (dosRule.isTriggered(logs) && isNewAlert(ipAddress, "DOS_ATTACK")) {
            DetectionAlert alert = DetectionAlert.builder()
                    .ipAddress(ipAddress)
                    .username(ipAddress) // kept for dedup compatibility
                    .type("DOS_ATTACK")
                    .severity(Severity.CRITICAL)
                    .message("High number of requests from same IP")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
            log.warn("🚨 DOS_ATTACK detected from IP: {}", ipAddress);
        }
    }
}