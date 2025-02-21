package com.cug.cs.overseaprojectinformationsystem.dto;

import lombok.Data;

@Data
public class LoginFormDto {
    private String phone;
    private String code;
    private String password;
}
