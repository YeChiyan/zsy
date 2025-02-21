package com.cug.cs.overseaprojectinformationsystem.shiro;


import com.alibaba.fastjson.JSON;
import com.cug.cs.overseaprojectinformationsystem.bean.common.BaseRespVo;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import com.cug.cs.overseaprojectinformationsystem.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class JwtFilter3 extends BasicHttpAuthenticationFilter {

    /**
     * 是否允许访问
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        /*try {
            // 1. 验证token
            if (!executeLogin(request, response)) {
                return false;
            }

            // 2. 获取当前请求路径
            String requestURI = ((HttpServletRequest) request).getRequestURI();
            log.debug("当前访问路径: {}", requestURI);

            // 3. 获取当前用户角色
            String currentRole = JwtUtil.getRole(SecurityUtils.getSubject().getPrincipal().toString());
            log.debug("当前用户角色: {}", currentRole);

            // 4. 根据路径判断所需角色
            if (requestURI.startsWith("/auth/admin/") || requestURI.startsWith("/admin/")) {
                if (!"admin".equals(currentRole)) {
                    throw new UnauthorizedException("需要管理员权限");
                }
            } else if (requestURI.startsWith("/super/")) {
                if (!"superAdmin".equals(currentRole)) {
                    throw new UnauthorizedException("需要超级管理员权限");
                }
            } else if (requestURI.startsWith("/user/")) {
                if (!"user".equals(currentRole)) {
                    throw new UnauthorizedException("需要用户权限");
                }
            }

            return true;
        } catch (Exception e) {
            handleException(response, e);
            return false;
        }*/
        Subject subject = getSubject(request,response);
        String[] roles = (String[])mappedValue;
        if(roles == null || roles.length ==0){
            return true;
        }
        for(String role:roles){
            if(subject.hasRole(role)){
                return true;
            }
        }
        return false;
    }

    /**
     * 检查是否有token
     */
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        HttpServletRequest req = (HttpServletRequest) request;
        String token = req.getHeader("Authorization");
        return token != null && !token.isEmpty();
    }

    /**
     * 执行登录认证
     */
    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader("Authorization");

        if (token == null || token.isEmpty()) {
            return false;
        }

        try {
            JwtToken jwtToken = new JwtToken(token);
            getSubject(request, response).login(jwtToken);
            return true;
        } catch (Exception e) {
            log.error("Token验证失败: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 处理跨域
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        // 跨域时会首先发送一个OPTIONS请求，这里给OPTIONS请求直接返回正常状态
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            setHeader(httpServletResponse);
            return false;
        }

        return super.preHandle(request, response);
    }

    /**
     * 设置响应头
     */
    private void setHeader(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        response.setHeader("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Requested-With");
        response.setStatus(HttpStatus.OK.value());
    }

    /**
     * 处理异常
     */
    private void handleException(ServletResponse response, Exception e) {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setContentType("application/json;charset=utf-8");
        httpResponse.setHeader("Access-Control-Allow-Origin", "*");
        httpResponse.setHeader("Access-Control-Allow-Methods", "*");

        try (PrintWriter out = httpResponse.getWriter()) {
            ResponseUtil responseUtil = new ResponseUtil();
            
            if (e instanceof UnauthorizedException) {
                httpResponse.setStatus(HttpStatus.FORBIDDEN.value());
                responseUtil.setErrorMsg(403, "权限不足: " + e.getMessage());
            } else if (e instanceof AuthenticationException) {
                httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
                responseUtil.setErrorMsg(401, "认证失败: " + e.getMessage());
            } else {
                httpResponse.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                responseUtil.setErrorMsg(500, "服务器错误: " + e.getMessage());
            }

            out.write(JSON.toJSONString(responseUtil));
        } catch (IOException ex) {
            log.error("响应输出异常", ex);
        }
    }
}