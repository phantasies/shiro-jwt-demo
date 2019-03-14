package com.demo.utils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @Desc JWTUtil
 * @author fantao
 * @date 2018-11-28 14:12
 * @version
 */
public class JWTUtil {

    private static final String SECRET = "!@#$%^&*ABBFIQUALqwertyuiop";

    private static final String PAYLOAD = "payload";

    /**
     * 生成jwt token
     * @param object
     * @param seconds
     * @param <T>
     * @return
     */
    public static <T> String generateToken(T object, long seconds) {
        try {
            final Map<String, Object> claims = new HashMap<String, Object>();
            ObjectMapper mapper = new ObjectMapper();
            String jsonString = mapper.writeValueAsString(object);
            claims.put(PAYLOAD, jsonString);
            String jwt = Jwts.builder().setClaims(claims).setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + seconds * 1000))
                .signWith(SignatureAlgorithm.HS512, SECRET).compact();
            return jwt;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 获取签发时间
     * @param token
     * @return
     */
    public static Date getIssuedAt(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
            Date issuedAt = claims.getIssuedAt();
            return issuedAt;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 解码jwt token
     * @param token
     * @param classT
     * @param <T>
     * @return
     */
    public static <T> T decodeToken(String token, Class<T> classT) {
        try {
            Map<String, Object> claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token)
                .getBody();

            if (claims.containsKey(PAYLOAD)) {
                String json = (String) claims.get(PAYLOAD);
                ObjectMapper objectMapper = new ObjectMapper();
                return objectMapper.readValue(json, classT);
            }
            return null;
        } catch (Exception e) {
            //throw new IllegalStateException("Invalid Token. " + e.getMessage());
            Utils.errorStackTrace(e);
            return null;
        }

    }

    /**
     * 测试
     * @param args
     */
    public static void main(String[] args) throws InterruptedException {
        UserInfo testUserInfo = new UserInfo("user001", "13333333333");
        String token1 = JWTUtil.generateToken(testUserInfo, 3600);
        System.out.println("token1 encoded, with payload=" + token1);
        UserInfo testUserInfoDecoded = JWTUtil.decodeToken(token1, UserInfo.class);
        System.out.println("token1 decoded=" + testUserInfoDecoded);

        String testUsername = "user001";
        String token2 = JWTUtil.generateToken(testUsername, 3);
        System.out.println("token2 encoded, with payload=" + token2);

        //挂起5秒，让token2失效
        System.out.println("sleeping for 5 seconds");
        Thread.sleep(5000);
        String testUsernameDecoded = JWTUtil.decodeToken(token2, String.class);
        System.out.println("token2 decoded=" + testUsernameDecoded);
    }

    @Data
    @AllArgsConstructor
    static class UserInfo {
        private String username;
        private String msisdn;
    }
}
