package com.example.springsecurity.user.service;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.exception.AppException;
import com.example.springsecurity.exception.ErrorCode;
import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.configuration.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public String join(String userName, String password) {
        //중복체크
        userRepository.findByName(userName)
                .ifPresent(user -> {throw new AppException(ErrorCode.USERNAME_DUPLICATED, "이미 있는 회원");});

        //저장
        userRepository.save(User.builder()
                .name(userName)
                .password(bCryptPasswordEncoder.encode(password))
                .build());


        return "회원가입 성공";
    }

    public String login(String userName, String password) {
        //아이디(이름) 확인
        User user = userRepository.findByName(userName)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUND, "없는 회원"));

        //비밀번호 확인
        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD, "잘못된 비밀번호");
        }

        //토큰 발행
        String token = jwtTokenProvider.createToken(user.getName(), user.getRole().name());

        return token;
    }

}
