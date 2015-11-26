package com.l2cloud.core.security;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
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
        shiroFilter.setSecurityManager(securityManager());
        Map<String, Filter> filterMap = new HashMap<String, Filter>();
        filterMap.put("statelessAuthc", getStatelessAuthcFilter());
        shiroFilter.setFilters(filterMap);
        Map<String, String> FilterChainMap = new HashMap<String, String>();
        FilterChainMap.put("/**", "statelessAuthc");
        shiroFilter.setFilterChainDefinitionMap(FilterChainMap);
        return shiroFilter;
    }

    @Bean
    public StatelessAuthcFilter getStatelessAuthcFilter() {
        StatelessAuthcFilter stateless = new StatelessAuthcFilter();
        return stateless;
    }

    @Bean(name = "shiroDatabaseRealm")
    public CustomRealm getShiroRealm() {
        final CustomRealm realm = new CustomRealm();
        // realm.setCredentialsMatcher(credentialsMatcher());
        realm.setCachingEnabled(false);
        return realm;
    }

    @Bean(name = "subjectFactory")
    public StatelessDefaultSubjectFactory getStatelessDefaultSubjectFactory() {
        final StatelessDefaultSubjectFactory factory = new StatelessDefaultSubjectFactory();
        return factory;
    }

    @Bean(name = "sessionManager")
    public DefaultSessionManager getDefaultSessionManager() {
        DefaultSessionManager sessionManger = new DefaultSessionManager();
        sessionManger.setSessionValidationSchedulerEnabled(false);
        return sessionManger;
    }

    @Bean
    public MethodInvokingFactoryBean getMethodInvokingFactoryBean() {
        MethodInvokingFactoryBean bean = new MethodInvokingFactoryBean();
        bean.setStaticMethod("org.apache.shiro.SecurityUtils.setSecurityManager");
        bean.setArguments(new Object[] { securityManager() });
        return bean;

    }

    // securityManager安全管理器
    @Bean(name = "securityManager")
    public DefaultWebSecurityManager securityManager() {
        final DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(getShiroRealm());
        // securityManager.setCacheManager(getEhCacheManager());
        securityManager.setSubjectFactory(getStatelessDefaultSubjectFactory());
        securityManager.setSessionManager(getDefaultSessionManager());
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

    /*
     * @Bean(name = "formAuthenticationFilter") public
     * CustomFormAuthenticationFilter getFormAuthFilter() { final
     * CustomFormAuthenticationFilter formAuthFilter = new
     * CustomFormAuthenticationFilter(); formAuthFilter.setName("username");
     * formAuthFilter.setPasswordParam("password"); return formAuthFilter; }
     */

    // Shiro生命周期处理器
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

}