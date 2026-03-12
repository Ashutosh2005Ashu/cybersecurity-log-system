package com.ashutosh.cybersec.detection.entity;

import com.ashutosh.cybersec.common.enums.Severity;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "detection_alerts", indexes = {
        @Index(name = "idx_alert_type", columnList = "type"),
        @Index(name = "idx_alert_username", columnList = "username"),
        @Index(name = "idx_alert_created", columnList = "createdAt"),
        @Index(name = "idx_alert_dedup", columnList = "username, type, createdAt")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DetectionAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String ipAddress;

    @Column(nullable = false)
    private String type;     // BRUTE_FORCE, CREDENTIAL_STUFFING, SUSPICIOUS_LOGIN, DOS_ATTACK

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(nullable = false)
    private String message;

    @Builder.Default
    private boolean resolved = false;

    @Column(nullable = false)
    private LocalDateTime createdAt;
}
