package com.ashutosh.cybersec.detection.repository;

import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface DetectionAlertRepository
        extends JpaRepository<DetectionAlert, Long> {
    boolean existsByUsernameAndTypeAndCreatedAtAfter(
            String username,
            String type,
            LocalDateTime time
    );
    List<DetectionAlert> findByType(String type);
    
}
