package com.ashutosh.cybersec.admin.controller;

import com.ashutosh.cybersec.admin.service.AdminService;
import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.logs.entity.Log;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    // 🔴 Get all alerts
    @GetMapping("/alerts")
    public List<DetectionAlert> getAllAlerts() {
        return adminService.getAllAlerts();
    }

    // 🔴 Get alerts by type
    @GetMapping("/alerts/type/{type}")
    public List<DetectionAlert> getAlertsByType(@PathVariable String type) {
        return adminService.getAlertsByType(type);
    }

    // 🔴 Get all logs
    @GetMapping("/logs")
    public List<Log> getAllLogs() {
        return adminService.getAllLogs();
    }

    // 🔴 Get logs by username
    @GetMapping("/logs/{username}")
    public List<Log> getLogsByUsername(@PathVariable String username) {
        return adminService.getLogsByUsername(username);
    }
}