package com.ashutosh.cybersec.detection.repository;

import com.ashutosh.cybersec.detection.entity.DetectionAlert;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DetectionAlertRepository
        extends JpaRepository<DetectionAlert, Long> {
}
