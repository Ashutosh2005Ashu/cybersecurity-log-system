package com.ashutosh.cybersec.logs.repository;

import com.ashutosh.cybersec.logs.entity.Log;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LogRepository extends JpaRepository<Log, Long> {

    List<Log> findTop10ByUsernameAndActionOrderByTimestampDesc(
            String username,
            String action
    );
}
