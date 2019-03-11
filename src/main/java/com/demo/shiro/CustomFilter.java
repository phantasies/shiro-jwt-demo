package com.demo.shiro;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.alibaba.fastjson.JSON;
import com.demo.common.Consts;
import com.demo.common.Result;
import com.demo.component.LocaleMessage;
import com.demo.component.SpringContextHolder;
import com.demo.utils.CookieUtil;
import com.demo.utils.JWTUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * @Desc 登录过滤器
 * @author fantao
 * @date 2018年5月24日 下午2:00:04
 * @version 
 */
public class CustomFilter extends AuthenticatingFilter {

    private static Logger logger = LoggerFactory.getLogger(CustomFilter.class);

    //    @Autowired
    //    private LocaleMessage localeMessage;

    //是否需要验证登录
    private boolean isRequestWithJwt(ServletRequest request) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String token = CookieUtil.getCookieValue(httpRequest, Consts.TOKEN_NAME);
        return token != null;
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response,
                                      Object mappedValue) {
        if (this.isLoginRequest(request, response)) {
            return true;
        }
        if (!isRequestWithJwt(request)) {
            return false;
        }
        boolean allowed = false;
        try {
            allowed = executeLogin(request, response);
        } catch (IllegalStateException e) {
            logger.error("Not found any token");
        } catch (Exception e) {
            logger.error("Error occurs when login", e);
        }
        return allowed || super.isPermissive(mappedValue);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response)
        throws Exception {
        LocaleMessage localeMessage = SpringContextHolder.getBean("localeMessage");
        Result result = Result.build(500, localeMessage.getMessage("user.need.login"));
        response.setCharacterEncoding("UTF-8");
        try {
            response.getWriter().print(JSON.toJSONString(result, true));
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        //return true if the request should continue to be processed; false if the subclass will handle/render the response directly.
        return false;
    }

    /**
     * 登录成功需要刷新token
     * @param token
     * @param subject
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response)
        throws Exception {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        String newToken = null;
        if (token instanceof JWTToken) {
            JWTToken jwtToken = (JWTToken) token;
            String username = (String) subject.getPrincipal();
            boolean shouldRefresh = shouldTokenRefresh(JWTUtil.getIssuedAt((String) jwtToken
                .getPrincipal()));
            if (shouldRefresh) {
                newToken = JWTUtil.generateToken(username, Consts.TOKEN_EXPIRE_IN);
            }
        }
        if (StringUtils.isNotBlank(newToken)) {
            CookieUtil.setCookie(httpRequest, httpResponse, Consts.TOKEN_NAME, newToken);

        }
        return true;
    }

    //距离签发时间超过1小时则重新生成token
    protected boolean shouldTokenRefresh(Date issueAt) {
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(),
            ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(Consts.TOKEN_REFRESH_INTERVAL).isAfter(issueTime);
    }

    /**
     * 如果调用shiro的login认证失败，会回调这个方法，这里我们什么都不做，因为逻辑放到了onAccessDenied（）中。
     */
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
        return false;
    }

    /**
     * 创建jwt token
     * @param request
     * @param response
     * @return
     * @throws Exception
     */
    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response)
        throws Exception {
        String token = CookieUtil.getCookieValue((HttpServletRequest) request, Consts.TOKEN_NAME);
        JWTToken jwtToken = new JWTToken(token);
        return jwtToken;
    }

    /**
     * 对跨域提供支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        if (httpRequest.getHeader("Origin") != null) {
            String originHeader = URLEncoder.encode(httpRequest.getHeader("Origin"),
                StandardCharsets.UTF_8.displayName());
            httpResponse.setHeader("Access-control-Allow-Origin", originHeader);
        }
        httpResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpResponse.setHeader("Access-Control-Allow-Credentials", "true");

        if (httpRequest.getHeader("Access-Control-Request-Headers") != null) {
            String accessControlAllowHeaders = URLEncoder.encode(
                httpRequest.getHeader("Access-Control-Request-Headers"),
                StandardCharsets.UTF_8.displayName());
            httpResponse.setHeader("Access-Control-Allow-Headers", accessControlAllowHeaders);
        }

        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (httpRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }

}
