package com.demo.common;

/**
 * @Desc Consts
 * @author fantao
 * @date 2018-12-11 14:32
 * @version
 */
public class Consts {

    //用于承载jwt的cookie名
    public static final String TOKEN_NAME = "adminToken";

    //token超时时间
    public static final Long TOKEN_EXPIRE_IN = 3600 * 24 * 3l; //3天

    //token刷新时间
    public static final Long TOKEN_REFRESH_INTERVAL = 3600l;
}
