package com.example.springsecurity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionManager {
//    @ExceptionHandler(RuntimeException.class)
//    public ResponseEntity<?> runtimeExceptionHandler(RuntimeException e) { //? -> 리스펀스엔티티 바디에 뭐든지 들어갈 수 있다
//        return ResponseEntity.status(HttpStatus.CONFLICT)
//                .body(e.getMessage());
//    }

    @ExceptionHandler(AppException.class)
    public ResponseEntity<?> appExceptionHandler(AppException e) { //? -> 리스펀스엔티티 바디에 뭐든지 들어갈 수 있다
        return ResponseEntity.status(e.getErrorCode().getHttpStatus())
                .body(e.getErrorCode() + " " + e.getMessage());
                //리스펀스오브젝트로 랩핑을 할 수도 있는데 일단 이렇게 처리
    }
}
