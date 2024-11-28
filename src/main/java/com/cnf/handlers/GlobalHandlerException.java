package com.cnf.handlers;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalHandlerException {
    @ExceptionHandler(com.cnf.exception.NotFoundException.class)
    public ResponseEntity<?> handleNotFoundException(com.cnf.exception.NotFoundException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", ex.getMessage());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("path", ex.getStackTrace()[0].getClassName() + "." + ex.getStackTrace()[0].getMethodName());
        body.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.badRequest().body(body);
    }

}
