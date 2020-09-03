package org.springframework.security.boot.utils;

import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections4.MapUtils;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * Subject Utils
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("unchecked")
public class SubjectUtils {
	
	public static SecurityContext getSecurityContext(){
		return SecurityContextHolder.getContext();
	}
	
	public static Authentication getAuthentication(){
		return getSecurityContext().getAuthentication();
	}
	
	public static <T> T getPrincipal(Class<T> clazz){
		Object principal = getAuthentication().getPrincipal();
		// 自身类.class.isAssignableFrom(自身类或子类.class) 
		if( clazz.isAssignableFrom(principal.getClass()) ) {
			return (T)principal;
		}
		return null;
	}
	
	public static <T> T getPrincipal(Authentication authentication, Class<T> clazz){
		Object principal = authentication.getPrincipal();
		// 自身类.class.isAssignableFrom(自身类或子类.class) 
		if( clazz.isAssignableFrom(principal.getClass()) ) {
			return (T)principal;
		}
		return null;
	}
	
	public static String getProfileString(Authentication authentication, String key) {
		SecurityPrincipal principal = SubjectUtils.getPrincipal(authentication, SecurityPrincipal.class);
		return MapUtils.getString(principal.getProfile(), key);
	}
	
	public static int getProfileInt(Authentication authentication, String key) {
		SecurityPrincipal principal = SubjectUtils.getPrincipal(authentication, SecurityPrincipal.class);
		return MapUtils.getIntValue(principal.getProfile(), key);
	}
	
	public static Double getProfileDouble(Authentication authentication, String key) {
		SecurityPrincipal principal = SubjectUtils.getPrincipal(authentication, SecurityPrincipal.class);
		return MapUtils.getDouble(principal.getProfile(), key);
	}
	
	public static Object getPrincipal(){
		Authentication authentication = getAuthentication();
		return authentication == null ? null : authentication.getPrincipal();
	}
	
	public static String getProfileString(String key) {
		SecurityPrincipal principal = SubjectUtils.getPrincipal( SecurityPrincipal.class);
		return MapUtils.getString(principal.getProfile(), key);
	}
	
	public static int getProfileInt(String key) {
		SecurityPrincipal principal = SubjectUtils.getPrincipal( SecurityPrincipal.class);
		return MapUtils.getIntValue(principal.getProfile(), key);
	}
	
	public static Double getProfileDouble(String key) {
		SecurityPrincipal principal = SubjectUtils.getPrincipal( SecurityPrincipal.class);
		return MapUtils.getDouble(principal.getProfile(), key);
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
	
	/*
	 * 检查target类型对是否是给出对象类型数组中任意一个的类型的子类或者子接口
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
	
}
