package org.springframework.security.boot.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import reactor.core.publisher.Mono;

/**
 * Reactive Subject Utils
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class ReactiveSubjectUtils {
	
	private static MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private static final String EMPTY = "";
	
	public static Mono<SecurityContext> getSecurityContext(){
		return ReactiveSecurityContextHolder.getContext();
	}
	
	public static Mono<Authentication> getAuthentication(){
		return getSecurityContext()
				.switchIfEmpty(Mono.error(new IllegalStateException("ReactiveSecurityContext is empty")))
                .map(SecurityContext::getAuthentication);
	}
	
	public static <T> Mono<T> getPrincipal(Class<T> clazz){
		return getAuthentication()
				.switchIfEmpty(Mono.error(new IllegalStateException("Authentication is empty")))
				.map(Authentication::getPrincipal).cast(clazz);
	}
	
	public static Mono<Object> getPrincipal(){
		return getAuthentication()
				.map(Authentication::getPrincipal);
	}
	
	public static boolean isAuthenticated(){
		return getAuthentication()
				.map(Authentication::isAuthenticated)
				.block();
	}
	
	/**
	 * 检查target类型对是否是给出对象类型数组中任意一个的类型的子类或者子接口
	 * @param target
	 * @param classes
	 * @return
	 */
	public static boolean isAssignableFrom(Class<?> target, Class<?> ... classes) {
		if(target != null && classes != null) {
			for (Class<?> clazz : classes) {
				/*
				 *	假设有两个类Class1和Class2。Class1.isAssignableFrom(Class2)表示:
    			 *	1、类Class1和Class2是否相同。
    			 *	2、Class1是否是Class2的父类或接口 
				 */
				// clazz是否和target类型相同或者，clazz是否是target的父类或接口 
				if(clazz != null && clazz.isAssignableFrom(target)) {
					return true;
				};
			}
		}
		return false;
	}
	
	public static Map<String, Object> tokenMap(Mono<Authentication> authentication, String token){
		
		
		Map<String, Object> tokenMap = new HashMap<String, Object>(16);
		
		tokenMap.put("code", AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
		tokenMap.put("msg", messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey()));
		tokenMap.put("status", "success");

		UserDetails userDetails = authentication
			.map(Authentication::getPrincipal)
			.cast(UserDetails.class)
			.block();
		
		// 账号首次登陆标记
		if(SecurityPrincipal.class.isAssignableFrom(userDetails.getClass())) {
			SecurityPrincipal securityPrincipal = (SecurityPrincipal) userDetails;
			tokenMap.put("initial", securityPrincipal.isInitial());
			tokenMap.put("nickname", StringUtils.defaultString(securityPrincipal.getNickname(), EMPTY));
			tokenMap.put("userid", StringUtils.defaultString(securityPrincipal.getUserid(), EMPTY));
			tokenMap.put("userkey", StringUtils.defaultString(securityPrincipal.getUserkey(), EMPTY));
			tokenMap.put("usercode", StringUtils.defaultString(securityPrincipal.getUsercode(), EMPTY));
			tokenMap.put("username", userDetails.getUsername());
			tokenMap.put("perms", userDetails.getAuthorities());
			tokenMap.put("roleid", StringUtils.defaultString(securityPrincipal.getRoleid(), EMPTY ));
			tokenMap.put("role", StringUtils.defaultString(securityPrincipal.getRole(), EMPTY));
			tokenMap.put("roles", CollectionUtils.isEmpty(securityPrincipal.getRoles()) ? new ArrayList<>() : securityPrincipal.getRoles() );
			tokenMap.put("profile", CollectionUtils.isEmpty(securityPrincipal.getProfile()) ? new HashMap<>(0) : securityPrincipal.getProfile() );
			tokenMap.put("faced", securityPrincipal.isFace());
			tokenMap.put("faceId", StringUtils.defaultString(securityPrincipal.getFaceId(), EMPTY ));
			// JSON Web Token (JWT)
			tokenMap.put("token", token);
		} else {
			tokenMap.put("initial", false);
			tokenMap.put("nickname", EMPTY);
			tokenMap.put("userid", EMPTY);
			tokenMap.put("userkey", EMPTY);
			tokenMap.put("usercode", EMPTY);
			tokenMap.put("username", EMPTY);
			tokenMap.put("perms", new ArrayList<>(0));
			tokenMap.put("roleid", EMPTY);
			tokenMap.put("role", EMPTY);
			tokenMap.put("roles", new ArrayList<>(0));
			tokenMap.put("profile", new HashMap<>(0));
			tokenMap.put("faced", false);
			tokenMap.put("faceId", EMPTY);
			tokenMap.put("token", EMPTY);
		}
		
		return tokenMap;
		
	}
	
}
