package com.ashutosh.cybersec.logs.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "logs")
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
