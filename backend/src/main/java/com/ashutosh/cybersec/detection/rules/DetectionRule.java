package com.ashutosh.cybersec.detection.rules;

import com.ashutosh.cybersec.logs.entity.Log;

import java.util.List;

/**
 * Common contract for all detection rules.
 */
public interface DetectionRule {

    /**
     * Returns true if the rule's threat condition is met.
     */
    boolean isTriggered(List<Log> logs);

    /**
     * Human-readable name of this detection rule.
     */
    String getRuleName();
}

