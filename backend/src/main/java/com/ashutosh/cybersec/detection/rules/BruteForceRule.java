package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;

import java.util.List;

public class BruteForceRule {

    private static final int THRESHOLD = 5;

    public boolean isTriggered(List<Log> failedLogs) {
        return failedLogs.size() >= THRESHOLD;
    }
}
