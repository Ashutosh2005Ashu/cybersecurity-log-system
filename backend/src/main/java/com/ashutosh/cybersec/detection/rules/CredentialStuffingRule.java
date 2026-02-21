package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CredentialStuffingRule {

    private static final int USER_THRESHOLD = 5;   // unique users
    private static final int FAIL_THRESHOLD = 5;   // total failures

    public boolean isTriggered(List<Log> logs) {

        long totalFailures = logs.size();

        Set<String> uniqueUsers = logs.stream()
                .map(Log::getUsername)
                .collect(Collectors.toSet());

        return totalFailures >= FAIL_THRESHOLD &&
                uniqueUsers.size() >= USER_THRESHOLD;
    }
}