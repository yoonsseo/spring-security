package com.example.springsecurity.login.service;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.exception.AppException;
import com.example.springsecurity.exception.ErrorCode;
import com.example.springsecurity.login.dto.JoinRequestDto;
import com.example.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public String join(JoinRequestDto joinRequestDto) {
        //중복체크
        userRepository.findByName(joinRequestDto.getUserName())
                .ifPresent(user -> {throw new AppException(ErrorCode.USERNAME_DUPLICATED, "이미 있는 회원");});

        //저장
        userRepository.save(User.builder()
                .name(joinRequestDto.getUserName())
                .password(bCryptPasswordEncoder.encode(joinRequestDto.getPassword()))
                .build());


        return "회원가입 성공";
    }
}
