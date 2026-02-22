package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;
import org.springframework.stereotype.Component;

import java.util.List;
@Component
public class BruteForceRule {

    private static final int THRESHOLD = 5;

    public boolean isTriggered(List<Log> failedLogs) {
        return failedLogs.size() >= THRESHOLD;
    }
}
