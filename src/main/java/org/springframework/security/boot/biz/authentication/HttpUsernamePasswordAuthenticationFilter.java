package org.springframework.security.boot.biz.authentication;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 
 * @className	： RestUsernamePasswordAuthenticationFilter
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2018年3月10日 下午11:05:52
 * @version 	V1.0
 */
public class HttpUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	public static final String SPRING_SECURITY_FORM_CAPTCHA_KEY = "captcha";

	private String captchaParameter = SPRING_SECURITY_FORM_CAPTCHA_KEY;
	
	private static Logger logger = LoggerFactory.getLogger(HttpUsernamePasswordAuthenticationFilter.class);
	private final ObjectMapper objectMapper;
	private boolean captchaRequired = false;
	private CaptchaResolver captchaResolver;
	private boolean postOnly = true;
	private boolean restOnly = false;
	
	// ~ Constructors
	// ===================================================================================================

	public HttpUsernamePasswordAuthenticationFilter(String defaultProcessUrl, ObjectMapper mapper) {
		super();
		this.objectMapper = mapper;
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		if (isPostOnly() && !WebUtils.isPostRequest(request) ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not supported. Request method: " + request.getMethod());
			}
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
		
		if (isRestOnly() && !WebUtils.isAjaxRequest(request) ) {
			throw new AuthenticationServiceException("Authentication Request support XMLHttpRequest only");
		}

		try {

			UsernamePasswordAuthenticationToken authRequest = null;
			// XMLHttpRequest + Post
			if(WebUtils.isPostRequest(request) && WebUtils.isAjaxRequest(request)) {
				
				HttpLoginRequest loginRequest = objectMapper.readValue(request.getReader(), HttpLoginRequest.class);
				if (!StringUtils.hasText(loginRequest.getUsername()) || !StringUtils.hasText(loginRequest.getPassword())) {
					throw new AuthenticationServiceException("Username or Password not provided");
				}
				
				if(isCaptchaRequired() ) {

					if(!StringUtils.hasText(loginRequest.getCaptcha())) {
						throw new AuthenticationServiceException("Captcha not provided");
					}  
					
					if(captchaResolver != null && !captchaResolver.validCaptcha(request, loginRequest.getCaptcha())) {
						throw new AuthenticationServiceException("Invalid Captcha");
					}
					
				}
				
				authRequest = new UsernamePasswordAuthenticationToken( loginRequest.getUsername(), loginRequest.getPassword());

			} else {
				
		 		String captcha = obtainCaptcha(request);
		 		if(isCaptchaRequired() ) {

					if(!StringUtils.hasText(captcha)) {
						throw new AuthenticationServiceException("Captcha not provided");
					}  
					
					if(captchaResolver != null && !captchaResolver.validCaptcha(request, captcha)) {
						throw new AuthenticationServiceException("Invalid Captcha");
					}
					
				}
		 		
		 		String username = obtainUsername(request);
		 		String password = obtainPassword(request);
		 		if (username == null) {
		 			username = "";
		 		}

		 		if (password == null) {
		 			password = "";
		 		}

		 		username = username.trim();
				
		 		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
		            throw new AuthenticationServiceException("Username or Password not provided");
		        }
		 		
		 		authRequest = new UsernamePasswordAuthenticationToken( username, password);
		 		
			}

			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);

		} catch (JsonParseException e) {
			throw new AuthenticationServiceException(e.getMessage());
		} catch (JsonMappingException e) {
			throw new AuthenticationServiceException(e.getMessage());
		} catch (IOException e) {
			throw new AuthenticationServiceException(e.getMessage());
		}

	}

	/**
	 * Enables subclasses to override the composition of the captcha, such as by
	 * including additional values and a separator.
	 *
	 * @param request so that request attributes can be retrieved
	 *
	 * @return the captcha that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	protected String obtainCaptcha(HttpServletRequest request) {
		return request.getParameter(captchaParameter);
	}
	
	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If set to
	 * true, and an authentication request is received which is not a POST request, an
	 * exception will be raised immediately and authentication will not be attempted. The
	 * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
	 * authentication.
	 * <p>
	 * Defaults to <tt>true</tt> but may be overridden by subclasses.
	 */
	@Override
	public void setPostOnly(boolean postOnly) {
		super.setPostOnly(postOnly);
		this.postOnly = postOnly;
	}

	public boolean isPostOnly() {
		return postOnly;
	}
	
	public boolean isRestOnly() {
		return restOnly;
	}

	public void setRestOnly(boolean restOnly) {
		this.restOnly = restOnly;
	}

	public boolean isCaptchaRequired() {
		return captchaRequired;
	}

	public void setCaptchaRequired(boolean captchaRequired) {
		this.captchaRequired = captchaRequired;
	}

	public CaptchaResolver getCaptchaResolver() {
		return captchaResolver;
	}

	public void setCaptchaResolver(CaptchaResolver captchaResolver) {
		this.captchaResolver = captchaResolver;
	}

	public String getCaptchaParameter() {
		return captchaParameter;
	}

	public void setCaptchaParameter(String captchaParameter) {
		this.captchaParameter = captchaParameter;
	}
	
}
