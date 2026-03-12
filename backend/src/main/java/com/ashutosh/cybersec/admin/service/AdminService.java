package com.ashutosh.cybersec.admin.service;

import com.ashutosh.cybersec.common.enums.Severity;
import com.ashutosh.cybersec.common.exception.ResourceNotFoundException;
import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.detection.repository.DetectionAlertRepository;
import com.ashutosh.cybersec.logs.entity.Log;
import com.ashutosh.cybersec.logs.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final DetectionAlertRepository alertRepository;
    private final LogRepository logRepository;

    @Transactional(readOnly = true)
    public List<DetectionAlert> getAllAlerts() {
        return alertRepository.findAll();
    }

    @Transactional(readOnly = true)
    public List<DetectionAlert> getUnresolvedAlerts() {
        return alertRepository.findByResolvedFalseOrderByCreatedAtDesc();
    }

    @Transactional(readOnly = true)
    public List<DetectionAlert> getAlertsByType(String type) {
        return alertRepository.findByType(type);
    }

    @Transactional(readOnly = true)
    public List<DetectionAlert> getAlertsBySeverity(Severity severity) {
        return alertRepository.findBySeverity(severity);
    }

    @Transactional
    public void resolveAlert(Long id) {
        DetectionAlert alert = alertRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Alert not found with id: " + id));
        alert.setResolved(true);
        alertRepository.save(alert);
    }

    @Transactional(readOnly = true)
    public List<Log> getAllLogs() {
        return logRepository.findAll();
    }

    @Transactional(readOnly = true)
    public List<Log> getLogsByUsername(String username) {
        return logRepository.findByUsername(username);
    }
}