/*
package com.cug.cs.overseaprojectinformationsystem.filter;



import com.cug.cs.overseaprojectinformationsystem.constant.SysRetCodeConstants;
import com.cug.cs.overseaprojectinformationsystem.util.jwt.JwtTokenUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.server.ServerWebExchange;




@Component
public class JwtTokenFilter implements GlobalFilter, Ordered {
    private final Logger log = LoggerFactory.getLogger(JwtTokenFilter.class);
    @Autowired
    SkipUrlProperties skillUrlProperties;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //         // 获取实际请求的path路径
        String currentUrl = exchange.getRequest().getURI().getPath();
        // 判断是否应该拦截该请求，验证其Token
        if (shouldSkip(currentUrl, exchange.getRequest().getMethod())) {
            return chain.filter(exchange);
        }

        // 登录身份认证的逻辑
        log.info("需要认证的URL:{}",currentUrl);
        // 这个方法获取名为access_token的cookie，我们的JWT Token字符串存储在名access_token的存储
        HttpCookie access_token = exchange.getRequest().getCookies().getFirst("access_token");
        // exchange.getRequest().get
        if (access_token == null) {
            // 没有Token
            throw new GateWayException(SysRetCodeConstants.GET_TOKEN_FAILED.getCode(),
                    SysRetCodeConstants.GET_TOKEN_FAILED.getMessage());
        }

        // 从cookie中去JWT Token字符串
        String tokenStr = access_token.getValue();

        if (tokenStr == null || tokenStr.trim().length() == 0) {
            throw new GateWayException(SysRetCodeConstants.GET_TOKEN_FAILED.getCode(),
                    SysRetCodeConstants.GET_TOKEN_FAILED.getMessage());
        }


        // 获取Token字符串中的数据，它应该是一个json字符串
        //  会在JWT Token字符串，保存用户uid，username
        // {"uid":1, "username":"zs"}
        String userInfoJson = JwtTokenUtils.builder().token(tokenStr).build().freeJwt();

        // 将登录是放入JWT Token字符串中的用户信息，取出来，放入请求头中
        ServerWebExchange webExchange = putHeader(exchange, userInfoJson);
        return chain.filter(webExchange);
    }

    private ServerWebExchange putHeader(ServerWebExchange exchange, String userInfoJson) {

        ServerHttpRequest newServerRequest = exchange.getRequest()
                .mutate().header("user_info", userInfoJson).build();

        return exchange.mutate().request(newServerRequest).build();
    }

    */
/*
           返回false: 该请求需要被拦截，进行登录身份的验证
     *//*

    private boolean shouldSkip(String currentUrl, HttpMethod method) {

        // 验证登录，需要拦截
        if ("/user/login".equals(currentUrl.trim())
                && HttpMethod.GET.equals(method)) {
            return false;
        }
        //路径匹配器(简介SpringMvc拦截器的匹配器)
        //比如/oauth/** 可以匹配/oauth/token    /oauth/check_token等
        PathMatcher pathMatcher = new AntPathMatcher();
        for (String skipPath : skillUrlProperties.getSkipUrls()) {
            if (pathMatcher.match(skipPath, currentUrl)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
*/
