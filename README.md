# shiro-jwt-demo
基于shiro+jwt的后台管理系统登录与权限模块

## JWT介绍 ##
JWT(JSON Web Token)是目前最流行的跨域身份验证解决方案，是以JSON 对象为载体的轻量级开放标准（RFC 7519）。
一个JWT token包含头信息、荷载信息、签名信息。特点如下：

--紧凑性：体积较小、意味着传输速度快，可以作为POST参数或放置在HTTP头。
--自包含性：有效的负载包含用户鉴权所需所有信息，避免多次查询数据库。
--安全性：支持对称和非对称方式(HMAC、RSA)进行消息摘要签名。
--标准化：开放标准，多语言支持，跨平台。

适用场景如下：
--无状态、分布式鉴权，比如rest api系统、微服务系统。
--方便解决跨域授权的问题，比如SSO单点登陆。
--JWT只是消息协议，不牵涉到会话管理和存储机制，所以单体WEB应用还是推荐session-cookie机制。

编解码示例：见JWTUtil.java


## shiro集成核心类 ##

Authentication: 认证，即根据用户名和密码验证用户是否可以进入系统

Authorization：授权，即根据role和permission验证用户是否有权限调用某个功能

ShiroConfiguration.java 提供shiro全局配置，包括4个过滤器、ehCache缓存bean、realm、AOP支持

CustomFilter.java: 认证过滤器，继承AuthenticatingFilter，核心调用链：

1. CustomFilter.isAccessAllowed
2. 调用其父类的AuthenticatingFilter.executeLogin
3. 调用subject.login(token)，
4. 调用CustomRealm.doGetAuthenticationInfo, 该方法实现从cookie中获取JWT token，并进行解码验证，验证通过即代表用户身份合法

CustomPermissionFilter.java: 权限过滤器，继承AccessControlFilter，实现isAccessAllowed方法

CustomRoleFilter.java: 角色过滤器，角色是一组权限的组合，在数据库中映射，继承AccessControlFilter，实现isAccessAllowed方法

CustomLogoutFilter.java: 登出过滤器

CustomRealm.java: 认证信息获取、授权信息获取及验证，实现doGetAuthorizationInfo和doGetAuthenticationInfo两个方法

## 登录处理 ##
LoginController.java: 
1. 获取用户输入的用户名和密码，到数据库中验证密码是否准确
2. 验证通过，调用JWTUtil.generateToken生成token，其中payload是username(String对象)，并设置有效期3天
3. 写入cookie，名称为adminToken

## 业务逻辑 ##
TestController.java:
1. 浏览器调用接口，携带cookie: adminToken=value
2. @RequiresAuthentication和@RequiresPermissions("xxx")注解会调用CustomFilter和CustomPermissionFilter来进行认证与授权判断，其中xxx是功能名，在数据库中配置
3. 暂未使用角色授权判断


## 示例 ##
登录请求：
```
http://192.168.100.222:8088/api/login
POST: username=user001&password=user001
````
响应：
```
{
    "status": 200,
    "msg": "OK",
    "data": {
        "permissions": [
            "function1_menu",
            "function1_query"
        ]
    }
}
````
调用查询功能function1_query请求
```
http://192.168.100.222:8088/api/test/query
```
响应：
```
{
    "status": 200,
    "msg": "OK",
    "data": "查询功能授权通过"
}
```
调用创建功能function1_edit请求
```
http://192.168.100.222:8088/api/test/add
```
响应：
```
{"msg":"权限不足","status":500}
```
删除cookie:adminToken=value，再次调用查询功能function1_query请求
```
http://192.168.100.222:8088/api/test/query
```
响应：
```
{
	"msg":"请先登录",
	"status":500
}
```


## 其他 ##
1. 支持多语言
2. 通过AOP捕获Controller抛出的异常，封装为json
3. 数据库建表及示例数据位于sql目录下
