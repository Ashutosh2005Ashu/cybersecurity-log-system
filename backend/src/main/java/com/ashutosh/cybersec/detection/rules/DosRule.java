package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class DosRule implements DetectionRule {

    private static final int THRESHOLD = 10; // requests per minute

    /**
     * Logs are pre-filtered to the time window by the caller.
     */
    @Override
    public boolean isTriggered(List<Log> logs) {
        return logs.size() >= THRESHOLD;
    }

    @Override
    public String getRuleName() {
        return "DOS_ATTACK";
    }
}