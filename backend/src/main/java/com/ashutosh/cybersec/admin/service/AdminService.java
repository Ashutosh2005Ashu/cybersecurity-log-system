package com.ashutosh.cybersec.admin.service;

import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.detection.repository.DetectionAlertRepository;
import com.ashutosh.cybersec.logs.entity.Log;
import com.ashutosh.cybersec.logs.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final DetectionAlertRepository alertRepository;
    private final LogRepository logRepository;

    // 🔴 Get all alerts
    public List<DetectionAlert> getAllAlerts() {
        return alertRepository.findAll();
    }

    // 🔴 Get all logs
    public List<Log> getAllLogs() {
        return logRepository.findAll();
    }

    // 🔴 Filter alerts by type
    public List<DetectionAlert> getAlertsByType(String type) {
        return alertRepository.findByType(type);
    }

    // 🔴 Filter logs by username
    public List<Log> getLogsByUsername(String username) {
        return logRepository.findByUsername(username);
    }
}