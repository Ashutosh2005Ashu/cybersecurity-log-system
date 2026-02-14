package com.ashutosh.cybersec.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private final StringRedisTemplate redisTemplate;

    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCK_TIME_MINUTES = 5;

    private String getKey(String username) {
        return "login:attempts:" + username;
    }

    public void loginFailed(String username) {
        String key = getKey(username);

        Long attempts = redisTemplate.opsForValue().increment(key);

        if (attempts != null && attempts == 1) {
            redisTemplate.expire(key, LOCK_TIME_MINUTES, TimeUnit.MINUTES);
        }
    }

    public void loginSucceeded(String username) {
        redisTemplate.delete(getKey(username));
    }

    public boolean isBlocked(String username) {
        String key = getKey(username);
        String attemptsStr = redisTemplate.opsForValue().get(key);

        if (attemptsStr == null) return false;

        int attempts = Integer.parseInt(attemptsStr);
        return attempts >= MAX_ATTEMPTS;
    }
}
