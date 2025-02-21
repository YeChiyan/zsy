package com.cug.cs.overseaprojectinformationsystem.cotroller;

import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseData;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import com.cug.cs.overseaprojectinformationsystem.dto.KaptchaCodeResponse;
import com.cug.cs.overseaprojectinformationsystem.form.KaptchaCodeRequest;
import com.cug.cs.overseaprojectinformationsystem.service.IKaptchaService;
import com.cug.cs.overseaprojectinformationsystem.util.CookieUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;

/**
 * @description: TODO
 * @author: ShengHui
 * @date: 2023-09-18  21:13
 */
@RestController
@RequestMapping("/user")
@Slf4j
public class CaptchaController {
    @Autowired
    IKaptchaService kaptchaService;
    
    /**
     * 获取验证码
     */
    @GetMapping("/kaptcha")
    public ResponseData getKaptchaCode(HttpServletResponse response,HttpServletRequest request) {
        log.info("获取请求路径");
        log.info(request.getRequestURI());

        KaptchaCodeResponse kaptchaCodeResponse = kaptchaService.getKaptchaCode();
        Cookie cookie = CookieUtil.genCookie("kaptcha_uuid", kaptchaCodeResponse.getUuid(), "/", 60);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
        return new ResponseUtil<>().setData(kaptchaCodeResponse.getImageCode());
        
    }
    
    @PostMapping("/kaptcha")
    public ResponseData validKaptchaCode(@NotNull @RequestBody String code, HttpServletRequest httpServletRequest) {
        KaptchaCodeRequest request = new KaptchaCodeRequest();
        String uuid = CookieUtil.getCookieValue(httpServletRequest, "kaptcha_uuid");
        request.setUuid(uuid);
        request.setCode(code);
        kaptchaService.validateKaptchaCode(request);
        return new ResponseUtil<>().setData(null);
    }
}
