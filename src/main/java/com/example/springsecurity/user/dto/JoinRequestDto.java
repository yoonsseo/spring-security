package com.example.springsecurity.user.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class JoinRequestDto {
    private String userName;
    private String password;
}
