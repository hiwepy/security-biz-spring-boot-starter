package org.springframework.security.boot.utils;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Subject Utils
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class SubjectUtils {
	
	private static MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private static final String EMPTY = "";
	
	public static SecurityContext getSecurityContext(){
		return SecurityContextHolder.getContext();
	}
	
	public static Authentication getAuthentication(){
		return SecurityContextHolder.getContext().getAuthentication();
	}
	
	@SuppressWarnings("unchecked")
	public static <T> T getPrincipal(Class<T> clazz){
		Object principal = getAuthentication().getPrincipal();
		// 自身类.class.isAssignableFrom(自身类或子类.class) 
		if( clazz.isAssignableFrom(principal.getClass()) ) {
			return (T)principal;
		}
		return null;
	}
	
	public static Object getPrincipal(){
		Authentication authentication = getAuthentication();
		return authentication == null ? null : authentication.getPrincipal();
	}
	
	public static boolean isAuthenticated(){
		Authentication authentication = getAuthentication();
		return authentication == null ? false : authentication.isAuthenticated();
	}
	
	public static ServletRequestAttributes getRequestAttributes() {
		return (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();   
	}
	
	public static HttpServletRequest getRequest() {
		return getRequestAttributes().getRequest();   
	}
	 
	public static HttpServletResponse getResponse() {
		return ((ServletWebRequest)RequestContextHolder.getRequestAttributes()).getResponse();
	}
	
	public static HttpSession getSession(boolean create){
		return getRequest().getSession(create);
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
	
	/**
	 * 登陆成功后重新生成session【基于安全考虑】
	 * @param request {@link HttpServletRequest} instance
	 * @param oldSession Old {@link Session} instance
	 * @return {@link Session} instance
	 */
	public static HttpSession copySession(HttpServletRequest request, HttpSession oldSession) {
		Map<String, Object> attributes = new LinkedHashMap<String, Object>();

		Enumeration<String> keys = oldSession.getAttributeNames();
		while (keys.hasMoreElements()) {
			String key = keys.nextElement();
			Object value = oldSession.getAttribute(key);
			if (value != null) {
				attributes.put(key, value);
			}
		}
		oldSession.invalidate();
		// restore the attributes:
		HttpSession newSession = request.getSession();

		for (String key : attributes.keySet()) {
			newSession.setAttribute(String.valueOf(key), attributes.get(key));
		}
		return newSession;
	}
	
	public static Map<String, Object> tokenMap(Authentication authentication, String token){
		
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		
		Map<String, Object> tokenMap = new HashMap<String, Object>(16);
		
		tokenMap.put("code", AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
		tokenMap.put("msg", messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey()));
		tokenMap.put("status", "success");
		
		// 账号首次登陆标记
		if(SecurityPrincipal.class.isAssignableFrom(userDetails.getClass())) {
			SecurityPrincipal securityPrincipal = (SecurityPrincipal) userDetails;
			tokenMap.put("initial", securityPrincipal.isInitial());
			tokenMap.put("alias", StringUtils.defaultString(securityPrincipal.getAlias(), EMPTY));
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
			tokenMap.put("alias", "匿名账户");
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
