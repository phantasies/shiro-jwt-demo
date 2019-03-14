package com.demo.shiro;

import java.util.Arrays;

import com.demo.model.SysUser;
import com.demo.service.SysUserService;
import com.demo.utils.JWTUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @Desc 认证与授权实现
 * @author fantao
 * @date 2018年5月16日 下午2:56:19
 * @version 
 */
@Component
public class CustomRealm extends AuthorizingRealm {

    private static Logger logger = LoggerFactory.getLogger(CustomRealm.class);

    @Autowired
    private SysUserService sysUserService;

    public CustomRealm(CacheManager cacheManager) {
        super(cacheManager);
        setAuthenticationTokenClass(JWTToken.class);
    }

    /**
     * 授权，为当前登录的Subject查询角色和权限
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("##################执行Shiro权限授权##################");
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        //获取用户名
        String username = (String) principalCollection.getPrimaryPrincipal();
        SysUser user = sysUserService.selectByUsername(username);
        if (user.getRole() != null) {
            String[] roles = StringUtils.split(user.getRole(), ",");
            for (int i = 0; i < roles.length; i++) {
                authorizationInfo.addRole(roles[i]);
                String permissions = sysUserService.selectPermissionsByRoleName(roles[i]);
                if (StringUtils.isNotEmpty(permissions)) {
                    authorizationInfo.addStringPermissions(Arrays.asList(StringUtils.split(
                        permissions, ",")));
                }
            }
            return authorizationInfo;
        }
        return null;
    }

    /**
     * 认证，用于携带jwt token登录
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
        throws AuthenticationException {
        System.out.println("##################执行Shiro认证##################");

        //解码jwt token
        String token = (String) authenticationToken.getCredentials();
        String username = JWTUtil.decodeToken(token, String.class);
        if (username == null) {
            throw new AuthenticationException("token invalid");
        }

        //走一遍数据库
        //        String username = (String) authenticationToken.getPrincipal();
        SysUser sysUser = sysUserService.selectByUsername(username);
        if (sysUser == null) {
            //账户不存在
            throw new AccountException("user.login.failed");
        }
        return new SimpleAuthenticationInfo(username, token, getName());
    }

    /*    @PostConstruct
        public void initCredentialsMatcher() {
            //重写shiro的密码验证
            setCredentialsMatcher(new CustomCredentialsMatcher());
        }*/

}
