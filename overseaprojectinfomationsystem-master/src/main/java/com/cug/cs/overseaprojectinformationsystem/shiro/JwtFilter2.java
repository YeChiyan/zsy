package com.cug.cs.overseaprojectinformationsystem.shiro;

import com.alibaba.fastjson.JSON;
import com.cug.cs.overseaprojectinformationsystem.bean.common.BaseRespVo;
import com.cug.cs.overseaprojectinformationsystem.bean.common.ResponseUtil;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Slf4j
public class JwtFilter2 extends BasicHttpAuthenticationFilter implements Filter {

    // 是否允许访问
    @SneakyThrows
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        
        // 打印调试信息
        String[] roles = (String[]) mappedValue;
        log.debug("访问路径: {} | 需要的角色: {}", httpRequest.getRequestURI(), Arrays.toString(roles));
        
        try {
            Subject subject = getSubject(request, response);
            
            // 执行JWT认证
            if (!subject.isAuthenticated()) {
                String token = httpRequest.getHeader("Authorization");
                if (token == null || token.isEmpty()) {
                    throw new AuthorizationException("缺少访问令牌");
                }
                subject.login(new JwtToken(token));
            }
            
            // 角色验证
            if (roles != null && roles.length > 0) {
                for (String role : roles) {
                    if (subject.hasRole(role)) {
                        log.debug("角色 {} 验证通过", role);
                        return true;
                    }
                }
                throw new AuthorizationException("权限不足");
            }
            return true;
        } catch (Exception e) {
            handleException(response, e);
            return false;
        }
    }

    // 当访问被拒绝时调用
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return false; // 已通过handleException处理
    }

    // 异常处理
    private void handleException(ServletResponse response, Exception e) throws IOException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setHeader("Access-Control-Allow-Origin", "*");
        httpResponse.setHeader("Access-Control-Allow-Methods", "*");
        httpResponse.setContentType("application/json;charset=UTF-8");
        
        BaseRespVo<String> result = new BaseRespVo<>();
        ResponseUtil<Object> responseUtil = new ResponseUtil<>();
        if (e instanceof AuthorizationException) {
            httpResponse.setStatus(HttpStatus.FORBIDDEN.value());
            responseUtil.setErrorMsg(403,e.getMessage());
        } else {
            httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
            responseUtil.setErrorMsg(403,e.getMessage());
        }
        
        log.error("访问异常: {}", e.getMessage());
        httpResponse.getWriter().write(JSON.toJSONString(responseUtil));
    }

    // 处理CORS
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        httpResponse.setHeader("Access-Control-Allow-Origin", httpRequest.getHeader("Origin"));
        httpResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        httpResponse.setHeader("Access-Control-Allow-Headers", httpRequest.getHeader("Access-Control-Request-Headers"));
        
        if (httpRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }
}