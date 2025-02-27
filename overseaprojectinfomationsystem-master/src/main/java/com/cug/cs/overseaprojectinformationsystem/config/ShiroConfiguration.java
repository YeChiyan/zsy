package com.cug.cs.overseaprojectinformationsystem.config;

import com.cug.cs.overseaprojectinformationsystem.config.realm.AdminRealm;
import com.cug.cs.overseaprojectinformationsystem.config.realm.UserReaml;
import com.cug.cs.overseaprojectinformationsystem.filter.JwtFilter;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @description: TODO
 * @author: ShengHui
 * @date: 2023-09-01  23:55
 */
@Configuration
public class ShiroConfiguration {
    
    @Autowired
    AuthorizingRealm adminRealm;
    @Autowired
    AuthorizingRealm userReaml;
    /**
     *  注册shiroFilter
     * @param securityManager
     * @return org.apache.shiro.spring.web.ShiroFilterFactoryBean
     * @author huangshenghui
     * @since 2023/09/01 23:56
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        filterFactoryBean.setSecurityManager(securityManager);
    
        // 添加自定义过滤器
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("jwt", new JwtFilter());
        filterFactoryBean.setFilters(filterMap);
    
        // 配置过滤器链
        Map<String, String> filterRuleMap = new LinkedHashMap<>();
        // 允许匿名访问的接口
        filterRuleMap.put("/auth/login", "anon");
        filterRuleMap.put("/auth/register", "anon");
        // 需要角色验证的接口
        filterRuleMap.put("/auth/admin/**", "jwt,roles[admin]");  // 添加角色验证
        filterRuleMap.put("/auth/user/**", "jwt");  // 普通接口只需要验证token
        // 其他所有请求通过JWT过滤器
        filterRuleMap.put("/**", "jwt");
        
        filterFactoryBean.setFilterChainDefinitionMap(filterRuleMap);
        return filterFactoryBean;
    }
    
    @Bean
    public DefaultWebSecurityManager securityManager( DefaultWebSessionManager sessionManager) {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 给 SecurityManager, 默认认证器, 默认授权器都设置了 Realms
        // securityManager.setRealms(Arrays.asList(realm));
        securityManager.setRealms(Arrays.asList(adminRealm,userReaml));
        
        // 如果要使用自定义的认证器和授权器, 需要单独使用 set 方法, 还需要给自定义的认证器和授权器单独提供 Realms
        // securityManager.setAuthenticator();
        // securityManager.setAuthorizer();
        
        securityManager.setSessionManager(sessionManager);
        return securityManager;
    }
    
    @Bean
    public SystemSessionManager sessionManager() {
        // return new DefaultWebSessionManager();
        return new SystemSessionManager();
    }
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}
