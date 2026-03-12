package com.ashutosh.cybersec.logs.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "logs", indexes = {
        @Index(name = "idx_log_username_action_ts", columnList = "username, action, timestamp"),
        @Index(name = "idx_log_ip_action_ts", columnList = "ipAddress, action, timestamp"),
        @Index(name = "idx_log_ip", columnList = "ipAddress"),
        @Index(name = "idx_log_username", columnList = "username")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Log {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;

    private String action;
    // Examples:
    // LOGIN_SUCCESS
    // FAILED_LOGIN
    // SUSPICIOUS_ACTIVITY

    private String ipAddress;

    private LocalDateTime timestamp;

}
