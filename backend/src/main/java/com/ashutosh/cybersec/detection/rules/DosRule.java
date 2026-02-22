package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Component
public class DosRule {

    private static final int THRESHOLD = 10; // requests
    private static final int TIME_WINDOW_MINUTES = 1;

    public boolean isTriggered(List<Log> logs) {
        if (logs.size() < THRESHOLD) return false;

        LocalDateTime now = LocalDateTime.now();
        long count = logs.stream()
                .filter(log -> log.getTimestamp().isAfter(now.minusMinutes(TIME_WINDOW_MINUTES)))
                .count();

        return count >= THRESHOLD;
    }
}