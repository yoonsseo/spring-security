package com.example.springsecurity.controller;

import com.example.springsecurity.exception.AppException;
import com.example.springsecurity.exception.ErrorCode;
import com.example.springsecurity.login.dto.JoinRequestDto;
import com.example.springsecurity.login.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
class UserControllerTest {

    @Autowired MockMvc mockMvc;

    @MockBean UserService userService;

    @Autowired ObjectMapper objectMapper;
    //자바 오브젝트를 JSON으로 만들어주는 잭슨의 오브젝트

    @Test
    @DisplayName("회원가입 성공")
    void join() throws Exception{
        //given
        String userName = "yoonsseo";
        String password = "1234";

        //when, then
        mockMvc.perform(post("/api/v1/users/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new JoinRequestDto(userName, password)))) //HttpRequest에 어떤 값을 보낼 때는 byte로 보낸다
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("회원가입 실패 - 이름 중복")
    void join_fail() throws Exception{
        //given
        String userName = "yoonsseo";
        String password = "1234";

        when(userService.join(any()))
                .thenThrow(new AppException(ErrorCode.USERNAME_DUPLICATED, "중복된 이름"));

        //when, then
        mockMvc.perform(post("/api/v1/users/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new JoinRequestDto(userName, password)))) //HttpRequest에 어떤 값을 보낼 때는 byte로 보낸다
                .andDo(print())
                .andExpect(status().isConflict());
    }
}