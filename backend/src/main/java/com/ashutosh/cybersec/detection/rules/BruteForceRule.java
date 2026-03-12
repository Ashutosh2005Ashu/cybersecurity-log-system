package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;
import org.springframework.stereotype.Component;

import java.util.List;
@Component
public class BruteForceRule implements DetectionRule {

    private static final int THRESHOLD = 5;

    @Override
    public boolean isTriggered(List<Log> failedLogs) {
        return failedLogs.size() >= THRESHOLD;
    }

    @Override
    public String getRuleName() {
        return "BRUTE_FORCE";
    }
}
