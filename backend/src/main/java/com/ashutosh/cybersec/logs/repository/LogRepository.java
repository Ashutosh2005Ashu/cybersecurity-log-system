package com.ashutosh.cybersec.logs.repository;

import com.ashutosh.cybersec.logs.entity.Log;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface LogRepository extends JpaRepository<Log, Long> {

    List<Log> findByUsernameAndActionAndTimestampAfter(
            String username,
            String action,
            LocalDateTime time
    );
}
