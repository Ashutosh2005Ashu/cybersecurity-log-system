package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class SuspiciousLoginRule {

    public boolean isTriggered(List<Log> logs) {

        Set<String> uniqueIps = logs.stream()
                .map(Log::getIpAddress)
                .collect(Collectors.toSet());

        return uniqueIps.size() >= 2;
    }
}