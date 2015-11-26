package com.l2cloud.core.security;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @Description:shiro与Spring Boot整合的配置
 * @author Xu,Jin wind.j.xu@leaptocloud.com
 */
@Configuration
public class ShiroConfigurationBean {
    @Bean
    public ShiroFilterFactoryBean shiroFilter() {
        ShiroFilterFactoryBean shiroFilter = new ShiroFilterFactoryBean();
        // 注入securityManager安全管理器
        shiroFilter.setSecurityManager(securityManager());
        // 通过unauthorizedUrl指定没有权限操作时跳转页面
        shiroFilter.setUnauthorizedUrl("/refuse.html");
        shiroFilter.setLoginUrl("/login");
        Map<String, Filter> filterMap = new HashMap<String, Filter>();
        filterMap.put("authc", getFormAuthFilter());
        shiroFilter.setFilters(filterMap);
        // 自定义filter配置
        // 过虑器链定义，从上向下顺序执行，一般将/**放在最下边
        // shiroFilter.setFilterChainDefinitions();
        return shiroFilter;
    }

    @Bean(name = "shiroDatabaseRealm")
    public CustomRealm getShiroRealm() {
        final CustomRealm realm = new CustomRealm();
        realm.setCredentialsMatcher(credentialsMatcher());
        return realm;
    }

    // securityManager安全管理器
    @Bean(name = "securityManager")
    public DefaultWebSecurityManager securityManager() {
        final DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(getShiroRealm());
        securityManager.setCacheManager(getEhCacheManager());
        return securityManager;
    }

    @Bean(name = "credentialsMatcher")
    public HashedCredentialsMatcher credentialsMatcher() {
        final HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        return credentialsMatcher;
    }

    // 缓存管理器
    @Bean(name = "shiroEhcacheManager")
    public EhCacheManager getEhCacheManager() {
        EhCacheManager em = new EhCacheManager();
        /*
         * 
         * em.setCacheManagerConfigFile("classpath:ehcache-shiro.xml");
         */
        return em;
    }

    @Bean(name = "formAuthenticationFilter")
    public CustomFormAuthenticationFilter getFormAuthFilter() {
        final CustomFormAuthenticationFilter formAuthFilter = new CustomFormAuthenticationFilter();
        formAuthFilter.setName("username");
        formAuthFilter.setPasswordParam("password");
        return formAuthFilter;
    }

    /*
     * @Bean public DefaultWebSessionManager sessionManager() {
     * 
     * return null; }
     */
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

}