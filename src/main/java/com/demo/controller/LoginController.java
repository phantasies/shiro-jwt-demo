package com.demo.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.demo.common.Result;
import com.demo.exception.BusinessException;
import com.demo.model.SysUser;
import com.demo.service.SysUserService;
import com.demo.utils.CookieUtil;
import com.demo.utils.DesUtil;
import com.demo.utils.JWTUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @Desc LoginController
 * @author fantao
 * @date 2018-12-19 15:52
 * @version
 */
@Controller
@RequestMapping
public class LoginController {

    private static final Long TOKEN_EXPIRE_IN = 3600 * 24 * 1l; //1天

    @Autowired
    SysUserService sysUserService;

    /**
     * 登录
     * @param username
     * @param password
     * @return
     */
    @RequestMapping(path = "/api/login", method = RequestMethod.POST)
    @ResponseBody
    public Result login(String username, String password, HttpServletRequest request,
                        HttpServletResponse response) {
        //        Subject subject = SecurityUtils.getSubject();
        //        UsernamePasswordToken myToken = new UsernamePasswordToken(username, password);
        Assert.notNull(username, "username.is.empty");
        Assert.notNull(password, "password.is.empty");
        try {
            //不能使用subject.login，因为我们需要用过jwtToken来鉴权
            //subject.login(myToken);
            SysUser sysUser = sysUserService.selectByUsername(username);
            if (sysUser == null) {
                throw new BusinessException("user.login.failed");
            }
            if (!password.equals(DesUtil.decrypt(sysUser.getPassword()))) {
                throw new BusinessException("user.login.failed");
            }
            String token = JWTUtil.generateToken(sysUser.getUsername(), TOKEN_EXPIRE_IN);
            List<String> permissions = new ArrayList<>();
            if (sysUser.getRole() != null) {
                String[] roles = StringUtils.split(sysUser.getRole(), ",");
                for (int i = 0; i < roles.length; i++) {
                    String permissionsByRoleName = sysUserService
                        .selectPermissionsByRoleName(roles[i]);
                    if (StringUtils.isNotEmpty(permissionsByRoleName)) {
                        permissions.addAll(Arrays.asList(StringUtils.split(permissionsByRoleName,
                            ",")));
                    }
                }
            }

            CookieUtil.setCookie(request, response, "adminToken", token);

            Map<String, Object> map = new HashMap<String, Object>();
            map.put("permissions", permissions);
            return Result.build(200, "OK", map);

        } catch (IncorrectCredentialsException e) {
            return Result.build(500, "user.login.failed");
        } catch (LockedAccountException e) {
            return Result.build(500, "user.login.failed");
        } catch (AuthenticationException e) {
            return Result.build(500, "user.login.failed");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return Result.build(500, "service.system.error");
    }

}
