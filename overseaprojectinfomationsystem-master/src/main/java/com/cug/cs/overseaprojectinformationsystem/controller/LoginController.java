package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.alibaba.fastjson.JSON;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import com.cug.cs.overseaprojectinformationsystem.constant.UserRetCode;
import com.cug.cs.overseaprojectinformationsystem.dto.UserLoginResponse;
import com.cug.cs.overseaprojectinformationsystem.exception.ValidateException;
import com.cug.cs.overseaprojectinformationsystem.form.KaptchaCodeRequest;
import com.cug.cs.overseaprojectinformationsystem.form.UserLoginRequest;
import com.cug.cs.overseaprojectinformationsystem.service.IKaptchaService;
import com.cug.cs.overseaprojectinformationsystem.service.ILoginService;
import com.cug.cs.overseaprojectinformationsystem.util.CookieUtil;
import com.cug.cs.overseaprojectinformationsystem.util.jwt.JwtTokenUtils;
import org.apache.commons.lang3.StringUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
import com.cug.cs.overseaprojectinformationsystem.dto.UserLoginResponse;
import com.cug.cs.overseaprojectinformationsystem.form.KaptchaCodeRequest;
import com.cug.cs.overseaprojectinformationsystem.form.UserLoginRequest;
import com.cug.cs.overseaprojectinformationsystem.service.IKaptchaService;
import com.cug.cs.overseaprojectinformationsystem.service.ILoginService;
import com.cug.cs.overseaprojectinformationsystem.util.CookieUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @description: TODO 用户登录验证并设置token
 * @author: ShengHui
 * @date: 2023-09-08  20:53
 */

import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
import com.cug.cs.overseaprojectinformationsystem.dto.UserLoginResponse;
import com.cug.cs.overseaprojectinformationsystem.form.KaptchaCodeRequest;
import com.cug.cs.overseaprojectinformationsystem.form.UserLoginRequest;
import com.cug.cs.overseaprojectinformationsystem.service.IKaptchaService;
import com.cug.cs.overseaprojectinformationsystem.service.ILoginService;
import com.cug.cs.overseaprojectinformationsystem.util.CookieUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/user")
public class LoginController {
    @Autowired
    private IKaptchaService kaptchaService;
    
    @Autowired
    private ILoginService loginService;
    
    @PostMapping("/login")
    public ResponseData<UserLoginResponse> userLogin(@RequestBody UserLoginRequest request, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        // 1.校验验证码
        KaptchaCodeRequest kaptchaCodeRequest = new KaptchaCodeRequest();
        kaptchaCodeRequest.setCode(request.getCaptcha());
        String uuid = CookieUtil.getCookieValue(httpServletRequest, "kaptcha_uuid");
        kaptchaCodeRequest.setUuid(uuid);
        kaptchaService.validateKaptchaCode(kaptchaCodeRequest);
        
        // 2.验证用户名密码
        if (StringUtils.isBlank(request.getUserName()) || StringUtils.isBlank(request.getUserPwd())) {
            throw new ValidateException(UserRetCode.REQUISITE_PARAMETER_NOT_EXIST.getCode(),
                    UserRetCode.REQUISITE_PARAMETER_NOT_EXIST.getMessage());
        }

        UserLoginResponse response = loginService.login(request);
        
        // 3.设置cookie
        Cookie cookie = CookieUtil.genCookie("access_token", response.getToken(), "/", 86400);
        cookie.setHttpOnly(true);
        httpServletResponse.addCookie(cookie);
        
        return new ResponseUtil<UserLoginResponse>().setData(response, "success");
    }
    
    @GetMapping("/login")
    public ResponseData validateUserLogin(HttpServletRequest request) {
        String accessToken = CookieUtil.getCookieValue(request, "access_token");
        String userInfo = JwtTokenUtils.builder().token(accessToken).build().freeJwt();
        return new ResponseUtil<>().setData(JSON.parse(userInfo), "success");
    }
    
    @GetMapping("/loginOut")
    public ResponseData userLoginOut(HttpServletRequest request, HttpServletResponse response) {
        for (Cookie cookie : request.getCookies()) {
            cookie.setMaxAge(0);
            cookie.setPath("/");
            response.addCookie(cookie);
        }
        return new ResponseUtil<>().setData(null, "success");
    }
}
