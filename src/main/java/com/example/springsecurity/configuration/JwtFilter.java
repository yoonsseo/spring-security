package com.example.springsecurity.configuration;

import com.example.springsecurity.login.service.UserService;
import com.example.springsecurity.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {
    private final UserService userService;
    private final String secretKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Header에서 TOKEN 꺼내기
        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("authorization : {}", authorization);

        //TOKEN 없으면 권한 부여 전 리턴
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.error("잘못된 authorization 또는 없음");
            filterChain.doFilter(request, response);
            return;
        }

        //TOKEN 꺼내기 - "Bearer " 제거
        String token = authorization.split(" ")[1];
        log.info("TOKEN - {}", token);

        //TOKEN 유효시간 검증
        if (JwtUtil.isExpired(token, secretKey)) {
            log.error("TOKEN 만료");
            filterChain.doFilter(request, response);
            return;
        }

        //TOKEN에서 userName 꺼내기
        String userName = "";

        //권한 부여
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority("USER")));

        //Detail
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);
    }
}
