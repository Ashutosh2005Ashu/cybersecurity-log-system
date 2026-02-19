package com.ashutosh.cybersec.detection.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CredentialStuffingService {

    private final StringRedisTemplate redisTemplate;

    private static final int USERNAME_THRESHOLD = 5;
    private static final int WINDOW_SECONDS = 120;

    private String key(String ip) {
        return "login:ip:fail:" + ip;
    }

    public boolean recordFailedAttempt(String ip, String username) {

        String redisKey = key(ip);

        // Add username to Redis SET
        redisTemplate.opsForSet().add(redisKey, username);

        // Set expiry window
        redisTemplate.expire(redisKey, Duration.ofSeconds(WINDOW_SECONDS));

        // Get number of unique usernames
        Long size = redisTemplate.opsForSet().size(redisKey);

        return size != null && size >= USERNAME_THRESHOLD;
    }

    public void clear(String ip) {
        redisTemplate.delete(key(ip));
    }
}
