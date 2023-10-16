package com.example.springsecurity.controller;

import com.example.springsecurity.exception.AppException;
import com.example.springsecurity.exception.ErrorCode;
import com.example.springsecurity.login.dto.JoinRequestDto;
import com.example.springsecurity.login.dto.LoginRequestDto;
import com.example.springsecurity.login.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
class UserControllerTest {

    @Autowired
    MockMvc mockMvc;
    @MockBean
    UserService userService;
    @Autowired
    ObjectMapper objectMapper;
    //자바 오브젝트를 JSON으로 만들어주는 잭슨의 오브젝트

    @Test
    @DisplayName("회원가입 성공")
    @WithMockUser
    void join() throws Exception {
        //given
        String userName = "yoonsseo";
        String password = "1234";

        //when, then
        mockMvc.perform(post("/api/v1/users/join")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new JoinRequestDto(userName, password)))) //HttpRequest에 어떤 값을 보낼 때는 byte로 보낸다
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("회원가입 실패 - 이름 중복")
    @WithMockUser
    void join_fail() throws Exception {
        //given
        String userName = "yoonsseo";
        String password = "1234";

        when(userService.join(any(), any()))
                .thenThrow(new AppException(ErrorCode.USERNAME_DUPLICATED, "중복된 이름"));

        //when, then
        mockMvc.perform(post("/api/v1/users/join")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new JoinRequestDto(userName, password)))) //HttpRequest에 어떤 값을 보낼 때는 byte로 보낸다
                .andDo(print())
                .andExpect(status().isConflict());
    }

    @Test
    @DisplayName("로그인 성공")
    @WithMockUser
    void login() throws Exception {
        //given
        String userName = "spring";
        String password = "security";

        //when, then
        when(userService.join(any(), any()))
                .thenReturn("TOKEN");

        mockMvc.perform(post("/api/v1/users/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new LoginRequestDto(userName, password))))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("로그인 실패 - 아이디(이름) 없음")
    @WithMockUser
    void login_fail1() throws Exception {
        //given
        String userName = "hello";
        String password = "1234";

        //when, then
        when(userService.login(userName, password))
                .thenThrow(new AppException(ErrorCode.USER_NOT_FOUND, ""));

        mockMvc.perform(post("/api/v1/users/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new LoginRequestDto(userName, password))))
                .andDo(print())
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("로그인 실패 - 비밀번호 불일치")
    @WithMockUser
    void login_fail2() throws Exception {
        //given
        String userName = "hello";
        String password = "1234";

        //when, then
        when(userService.login(userName, password))
                .thenThrow(new AppException(ErrorCode.INVALID_PASSWORD, ""));

        mockMvc.perform(post("/api/v1/users/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new LoginRequestDto(userName, password))))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }
}