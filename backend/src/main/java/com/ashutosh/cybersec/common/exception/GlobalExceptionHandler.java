package com.ashutosh.cybersec.common.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    // ── Validation errors (400) ──────────────────────────────────────
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        Map<String, String> errors = new HashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            errors.put(fe.getField(), fe.getDefaultMessage());
        }

        return buildResponse(HttpStatus.BAD_REQUEST,
                "Validation failed", request.getRequestURI(), errors);
    }

    // ── Duplicate resource (409) ─────────────────────────────────────
    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ApiErrorResponse> handleDuplicate(
            DuplicateResourceException ex, HttpServletRequest request) {

        return buildResponse(HttpStatus.CONFLICT,
                ex.getMessage(), request.getRequestURI(), null);
    }

    // ── Resource not found (404) ─────────────────────────────────────
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleNotFound(
            ResourceNotFoundException ex, HttpServletRequest request) {

        return buildResponse(HttpStatus.NOT_FOUND,
                ex.getMessage(), request.getRequestURI(), null);
    }

    // ── Invalid credentials (401) ────────────────────────────────────
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCredentials(
            InvalidCredentialsException ex, HttpServletRequest request) {

        return buildResponse(HttpStatus.UNAUTHORIZED,
                ex.getMessage(), request.getRequestURI(), null);
    }

    // ── User blocked – brute force (429) ─────────────────────────────
    @ExceptionHandler(UserBlockedException.class)
    public ResponseEntity<ApiErrorResponse> handleBlocked(
            UserBlockedException ex, HttpServletRequest request) {

        return buildResponse(HttpStatus.TOO_MANY_REQUESTS,
                ex.getMessage(), request.getRequestURI(), null);
    }

    // ── Bad credentials from Spring Security (401) ───────────────────
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleBadCredentials(
            BadCredentialsException ex, HttpServletRequest request) {

        return buildResponse(HttpStatus.UNAUTHORIZED,
                "Invalid username or password", request.getRequestURI(), null);
    }

    // ── JWT exceptions (401) ─────────────────────────────────────────
    @ExceptionHandler({ExpiredJwtException.class, MalformedJwtException.class, SignatureException.class})
    public ResponseEntity<ApiErrorResponse> handleJwt(
            Exception ex, HttpServletRequest request) {

        return buildResponse(HttpStatus.UNAUTHORIZED,
                "Invalid or expired token", request.getRequestURI(), null);
    }

    // ── Access denied (403) ──────────────────────────────────────────
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest request) {

        return buildResponse(HttpStatus.FORBIDDEN,
                "Access denied", request.getRequestURI(), null);
    }

    // ── Catch-all (500) ──────────────────────────────────────────────
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleGeneric(
            Exception ex, HttpServletRequest request) {

        log.error("Unhandled exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);

        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred", request.getRequestURI(), null);
    }

    // ── Helper ───────────────────────────────────────────────────────
    private ResponseEntity<ApiErrorResponse> buildResponse(
            HttpStatus status, String message, String path,
            Map<String, String> validationErrors) {

        ApiErrorResponse body = ApiErrorResponse.builder()
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .path(path)
                .timestamp(LocalDateTime.now())
                .validationErrors(validationErrors)
                .build();

        return ResponseEntity.status(status).body(body);
    }
}

