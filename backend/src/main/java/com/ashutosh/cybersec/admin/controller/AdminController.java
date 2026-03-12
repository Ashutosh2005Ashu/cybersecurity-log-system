package com.ashutosh.cybersec.admin.controller;

import com.ashutosh.cybersec.admin.service.AdminService;
import com.ashutosh.cybersec.common.enums.Severity;
import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import com.ashutosh.cybersec.logs.entity.Log;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    // ── Alerts ───────────────────────────────────────────────────────

    @GetMapping("/alerts")
    public ResponseEntity<List<DetectionAlert>> getAllAlerts() {
        return ResponseEntity.ok(adminService.getAllAlerts());
    }

    @GetMapping("/alerts/unresolved")
    public ResponseEntity<List<DetectionAlert>> getUnresolvedAlerts() {
        return ResponseEntity.ok(adminService.getUnresolvedAlerts());
    }

    @GetMapping("/alerts/type/{type}")
    public ResponseEntity<List<DetectionAlert>> getAlertsByType(@PathVariable String type) {
        return ResponseEntity.ok(adminService.getAlertsByType(type));
    }

    @GetMapping("/alerts/severity/{severity}")
    public ResponseEntity<List<DetectionAlert>> getAlertsBySeverity(@PathVariable Severity severity) {
        return ResponseEntity.ok(adminService.getAlertsBySeverity(severity));
    }

    @PatchMapping("/alerts/{id}/resolve")
    public ResponseEntity<String> resolveAlert(@PathVariable Long id) {
        adminService.resolveAlert(id);
        return ResponseEntity.ok("Alert resolved");
    }

    // ── Logs ─────────────────────────────────────────────────────────

    @GetMapping("/logs")
    public ResponseEntity<List<Log>> getAllLogs() {
        return ResponseEntity.ok(adminService.getAllLogs());
    }

    @GetMapping("/logs/{username}")
    public ResponseEntity<List<Log>> getLogsByUsername(@PathVariable String username) {
        return ResponseEntity.ok(adminService.getLogsByUsername(username));
    }
}