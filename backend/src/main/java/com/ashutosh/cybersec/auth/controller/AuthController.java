package com.ashutosh.cybersec.auth.controller;

import com.ashutosh.cybersec.auth.dto.LoginRequest;
import com.ashutosh.cybersec.auth.dto.LoginResponse;
import com.ashutosh.cybersec.auth.dto.RegisterRequest;
import com.ashutosh.cybersec.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequest request) {
        String result = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {
        // Use server-detected IP — never trust client-sent IP
        String ip = resolveClientIp(httpRequest);

        String token = authService.login(
                request.getUsername(),
                request.getPassword(),
                ip
        );

        return ResponseEntity.ok(new LoginResponse(token));
    }

    private String resolveClientIp(HttpServletRequest request) {
        // TESTING ONLY — remove in production
        String testIp = request.getHeader("X-Test-IP");
        if (testIp != null && !testIp.isBlank()) {
            return testIp;
        }

        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

}
