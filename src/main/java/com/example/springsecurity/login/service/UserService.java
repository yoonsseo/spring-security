package com.example.springsecurity.login.service;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.exception.AppException;
import com.example.springsecurity.exception.ErrorCode;
import com.example.springsecurity.login.dto.JoinRequestDto;
import com.example.springsecurity.login.dto.LoginRequestDto;
import com.example.springsecurity.repository.UserRepository;
import com.example.springsecurity.util.JwtTokenUtil;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("${jwt.token.secret}")
    private String key;

    //토큰 만료 시간 1초 * 60 * 60 = 1시간
    private final static Long expireTimeMs = 1000 * 60 * 60L;

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

        //plain key → secret key
        String keyBase64Encoded = Base64.getEncoder().encodeToString(key.getBytes());
        SecretKey key = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());

        String token = JwtTokenUtil.createToken(userName, key, expireTimeMs);

        return token;
    }

}
