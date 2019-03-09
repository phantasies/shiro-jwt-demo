package com.demo.shiro;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * JWTToken
 */
public class JWTToken implements AuthenticationToken {

    //密钥
    private String token;

    /**
     * JWTToken
     * @param token
     */
    public JWTToken(String token) {
        this.token = token;
    }

    /**
     * getPrincipal
     * @return
     */
    @Override
    public Object getPrincipal() {
        return token;
    }

    /**
     * getCredentials
     * @return
     */
    public Object getCredentials() {
        return token;
    }
}
