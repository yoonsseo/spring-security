package com.example.springsecurity.login.controller;

import com.example.springsecurity.login.dto.JoinRequestDto;
import com.example.springsecurity.login.dto.LoginRequestDto;
import com.example.springsecurity.login.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/join")
    public ResponseEntity<String> join(@RequestBody JoinRequestDto joinRequestDto) {
        userService.join(joinRequestDto.getUserName(), joinRequestDto.getPassword());
        return ResponseEntity.ok().body("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequestDto loginRequestDto) {
        String token = userService.login(loginRequestDto.getUserName(), loginRequestDto.getPassword());
        return ResponseEntity.ok().body(token);
    }
}