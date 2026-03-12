package com.ashutosh.cybersec.logs.service;

import com.ashutosh.cybersec.logs.entity.Log;
import com.ashutosh.cybersec.logs.repository.LogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class LogService {

    private final LogRepository logRepository;

    @Transactional
    public void save(String username, String action, String ipAddress) {

        Log log = Log.builder()
                .username(username)
                .action(action)
                .ipAddress(ipAddress)
                .timestamp(LocalDateTime.now())
                .build();

        logRepository.save(log);
    }
}
