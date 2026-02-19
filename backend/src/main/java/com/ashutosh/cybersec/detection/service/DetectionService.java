package com.ashutosh.cybersec.detection.service;

import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.detection.repository.DetectionAlertRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class DetectionService {

    private final DetectionAlertRepository alertRepository;

    public void createBruteForceAlert(String username) {

        DetectionAlert alert = DetectionAlert.builder()
                .username(username)
                .type("BRUTE_FORCE")
                .message("Multiple failed login attempts detected")
                .createdAt(LocalDateTime.now())
                .build();

        alertRepository.save(alert);
    }
}
