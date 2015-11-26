package com.l2cloud.core.security;

import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import com.l2cloud.core.entity.TPrivilegeElement;
import com.l2cloud.core.entity.TUser;
import com.l2cloud.core.service.CommonService;

/**
 * @Description:shiro的自定义Realm
 * @author Xu,Jin wind.j.xu@leaptocloud.com
 */
public class CustomRealm extends AuthorizingRealm {

    @Autowired
    public CommonService commonService;

    // 设置realm的名称
    @Override
    public void setName(String name) {
        super.setName("customRealm");
    }

    /**
     * 用于认证,从数据库查询用户信息 如果查询到返回认证信息AuthenticationInfo
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException { // 将activeUser设置simpleAuthenticationInfo
        // token是用户输入的用户名和密码
        // 第一步从token中取出用户名
        String userId = (String) token.getPrincipal();
        // 第二步：根据用户输入的userCode从数据库查询
        TUser user = null;
        try {
            user = this.commonService.findUserByUserId(userId);
            // 如果查询不到返回null
            if (null != user) {
                String password = user.getPasswd();
                ActiveUser activeUser = new ActiveUser();
                activeUser.setUserId(user.getUserId());
                activeUser.setId(user.getId());
                activeUser.setUserName(user.getUserName());
                // 根据用户id取出菜单
                List<TPrivilegeElement> menus = null;
                this.commonService.findMenuListByLoginId(user.getUserId());
            } else {
                return null;

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // 用于授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        System.out.println("11111");
        return null;
    }

    // 清除缓存
    public void clearCached() {
        PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
        super.clearCache(principals);
    }

}
