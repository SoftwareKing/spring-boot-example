package com.l2cloud.core.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import com.l2cloud.core.util.HmacSHA256Utils;

/**
 * @Description:shiro的自定义Realm
 * @author Xu,Jin wind.j.xu@leaptocloud.com
 */
public class CustomRealm extends AuthorizingRealm {

    @Override
    public boolean supports(AuthenticationToken token) {
        // 仅支持StatelessToken类型的Token
        return token instanceof StatelessToken;
    }

    // 设置realm的名称
    @Override
    public void setName(String name) {
        super.setName("customRealm");
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 根据用户名查找角色，请根据需求实现
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        authorizationInfo.addRole("admin");
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        StatelessToken statelessToken = (StatelessToken) token;
        String username = statelessToken.getUsername();
        String key = getKey(username);// 根据用户名获取密钥（和客户端的一样）
        // 在服务器端生成客户端参数消息摘要
        String serverDigest = HmacSHA256Utils.digest(key, statelessToken.getParams());
        System.out.println("客户端Digest:" + statelessToken.getClientDigest());
        System.out.println("服务端Digest:" + serverDigest);
        // 然后进行客户端消息摘要和服务器端消息摘要的匹配
        return new SimpleAuthenticationInfo(username, serverDigest, getName());
    }

    private String getKey(String username) {// 得到密钥，此处硬编码一个
        if ("admin".equals(username)) {
            return "dadadswdewq2ewdwqdwadsadasd";
        }
        return null;
    }

    /*
     * // 用于认证,从数据库查询用户信息
     * 
     * @Override protected AuthenticationInfo
     * doGetAuthenticationInfo(AuthenticationToken token) throws
     * AuthenticationException { // 将activeUser设置simpleAuthenticationInfo
     * SimpleAuthenticationInfo simpleAuthenticationInfo = new
     * SimpleAuthenticationInfo(null, null, null, this.getName());
     * 
     * return simpleAuthenticationInfo; }
     * 
     * // 用于授权
     * 
     * @Override protected AuthorizationInfo
     * doGetAuthorizationInfo(PrincipalCollection principals) {
     * 
     * return null; }
     */
    // 清除缓存
    public void clearCached() {
        PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
        super.clearCache(principals);
    }

}
