package com.cug.cs.overseaprojectinformationsystem.shiro;

import com.alibaba.fastjson.JSON;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Slf4j
public class JwtFilter extends BasicHttpAuthenticationFilter {

    // 判断是否存在登录请求
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        HttpServletRequest req = (HttpServletRequest) request;
        String authorization = req.getHeader("token");
        return authorization != null;
    }

    // 执行登录
    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String authorization = httpServletRequest.getHeader("token");
        JwtToken token = new JwtToken(authorization);
        try {
            getSubject(request, response).login(token);
            return true;
        } catch (AuthenticationException e) {
            // 如果认证失败，返回 false
            return false;
        }
    }

    // 检查访问是否被允许
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
//        log.debug("Request path: {}", request.get());
        log.debug("Mapped value: {}", mappedValue); // 这里检查 mappedValue 是否正确传递
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURI = httpRequest.getRequestURI();
        
        // 打印调试信息
        log.debug("Checking access for: {}", requestURI);
        log.debug("Mapped roles: {}", Arrays.toString((String[]) mappedValue));

        if (isLoginAttempt(request, response)) {
            try {
                boolean loggedIn = executeLogin(request, response);
                if (!loggedIn) {
                    return false;
                }

                // 添加调试日志
                log.debug("Checking access for path: {}", ((HttpServletRequest) request).getRequestURI());
                
                Subject subject = getSubject(request, response);
                String[] rolesArray = (String[]) mappedValue;
                
                // 打印配置的角色要求
                log.debug("Required roles: {}", Arrays.toString(rolesArray));
                // 打印用户实际角色
//                log.debug("User roles: {}", JwtUtil.getRole(((JwtToken)subject.getPrincipals()).toString()));


                if (rolesArray == null || rolesArray.length == 0) {
                    return true;
                }

                for (String role : rolesArray) {
                    if (subject.hasRole(role)) {
                        log.debug("Role {} matched", role);
                        return true;
                    }
                }

                log.warn("Access denied - Insufficient permissions");
                responseError(response, "权限不足", HttpStatus.FORBIDDEN.value());
                return false;

            } catch (Exception e) {
                log.error("Authentication failed", e);
                responseError(response, "认证失败", HttpStatus.UNAUTHORIZED.value());
                return false;
            }
        }
        return true;
    }

    // 处理 CORS 和 OPTIONS 请求
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));

        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpServletResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }

    // 错误响应处理
    private void responseError(ServletResponse response, String message, int statusCode) {
        try {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            httpServletResponse.setStatus(statusCode);
            httpServletResponse.setHeader("Access-Control-Allow-Origin", "*");  // CORS
            httpServletResponse.setHeader("Access-Control-Allow-Methods", "*");  // CORS
            httpServletResponse.setContentType("application/json; charset=UTF-8");
            httpServletResponse.getWriter().write(JSON.toJSONString(new ResponseUtil().setErrorMsg(statusCode, message)));
        } catch (IOException e) {
            log.error("Error sending response", e);
        }
    }
}