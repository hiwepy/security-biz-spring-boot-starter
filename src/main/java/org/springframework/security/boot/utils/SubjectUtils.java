package org.springframework.security.boot.utils;

import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.boot.web.servlet.server.Session;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

public class SubjectUtils {

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
		return getAuthentication().getPrincipal();
	}
	
	public static boolean isAuthenticated(){
		return getAuthentication().isAuthenticated();
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
