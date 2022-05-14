# security-biz-spring-boot-starter

security starter for spring boot

### 组件简介

> 基于 Security 的 Spring Boot Starter 实现

主要 扩展Security与Spring Boot的整合，实现通过yaml配置即可实现权限拦截扩展，类似Shiro的 shiro.ini 配置方式

### 使用说明

##### 1、Spring Boot 项目添加 Maven 依赖

``` xml
<dependency>
	<groupId>com.github.hiwepy</groupId>
	<artifactId>security-biz-spring-boot-starter</artifactId>
	<version>1.1.2.RELEASE</version>
</dependency>
```

##### 2、在`application.yml`文件中增加如下配置

```yaml
spring:
  # Spring Security 配置
  security:
    # 默认路径拦截规则定义
    filter-chain-definition-map:
      '[/]' : anon
      '[/**/favicon.ico]' : anon
      '[/webjars/**]': anon
      '[/assets/**]' : anon
      '[/error*]' : anon
      '[/logo/**]' : anon
      '[/swagger-ui.html**]' : anon
      '[/swagger-resources/**]' : anon
      '[/doc.html**]' : anon
      '[/bycdao-ui/**]' : anon
      '[/v2/**]' : anon
      '[/kaptcha*]' : anon
      '[/actuator*]' : anon
      '[/actuator/**]' : anon
      '[/druid/*]' : ipaddr[192.168.1.0/24]
      '[/monitoring]' : roles[admin]
      '[/monitoring2]' : roles[1,admin]
      '[/monitoring3]' : perms[1,admin]
      '[/monitoring4]' : perms[1]
```

##### 3、使用示例

```java
 SecurityPrincipal principal = SubjectUtils.getPrincipal(SecurityPrincipal.class);
```

## Jeebiz 技术社区

Jeebiz 技术社区 **微信公共号**、**小程序**，欢迎关注反馈意见和一起交流，关注公众号回复「Jeebiz」拉你入群。

|公共号|小程序|
|---|---|
| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/qrcode_for_gh_1d965ea2dfd1_344.jpg)| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/gh_09d7d00da63e_344.jpg)|

