package com.ashutosh.cybersec.detection.service;

import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.detection.repository.DetectionAlertRepository;
import com.ashutosh.cybersec.detection.rules.BruteForceRule;
import com.ashutosh.cybersec.detection.rules.CredentialStuffingRule;
import com.ashutosh.cybersec.detection.rules.SuspiciousLoginRule;
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

    private final BruteForceRule bruteForceRule = new BruteForceRule();

    public void checkBruteForce(String username) {

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> recentFailedLogs =
                logRepository.findByUsernameAndActionAndTimestampAfter(
                        username,
                        "FAILED_LOGIN",
                        windowStart
                );

        if (bruteForceRule.isTriggered(recentFailedLogs)) {

            DetectionAlert alert = DetectionAlert.builder()
                    .username(username)
                    .type("BRUTE_FORCE")
                    .message("Multiple failed login attempts within 5 minutes")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
        }
    }
    public void checkCredentialStuffing(String ipAddress) {

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> failedLogs =
                logRepository.findByIpAddressAndActionAndTimestampAfter(
                        ipAddress,
                        "FAILED_LOGIN",
                        windowStart
                );

        CredentialStuffingRule rule = new CredentialStuffingRule();

        if (rule.isTriggered(failedLogs)) {

            DetectionAlert alert = DetectionAlert.builder()
                    .username("MULTIPLE_USERS")
                    .type("CREDENTIAL_STUFFING")
                    .message("Multiple login failures from same IP across users")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
        }
    }
    public void checkSuspiciousLogin(String username) {

        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(5);

        List<Log> successLogs =
                logRepository.findByUsernameAndActionAndTimestampAfter(
                        username,
                        "LOGIN_SUCCESS",
                        windowStart
                );

        SuspiciousLoginRule rule = new SuspiciousLoginRule();

        if (rule.isTriggered(successLogs)) {

            DetectionAlert alert = DetectionAlert.builder()
                    .username(username)
                    .type("SUSPICIOUS_LOGIN")
                    .message("Login from multiple IPs in short time")
                    .createdAt(LocalDateTime.now())
                    .build();

            alertRepository.save(alert);
        }
    }

}

