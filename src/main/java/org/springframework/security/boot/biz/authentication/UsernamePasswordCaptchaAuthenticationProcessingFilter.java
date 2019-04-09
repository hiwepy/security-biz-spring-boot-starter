package org.springframework.security.boot.biz.authentication;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaIncorrectException;
import org.springframework.security.boot.biz.exception.AuthenticationCaptchaNotFoundException;
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
 * 账号、密码、验证码认证过滤器
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class UsernamePasswordCaptchaAuthenticationProcessingFilter extends UsernamePasswordAuthenticationFilter {

	public static final String SPRING_SECURITY_FORM_CAPTCHA_KEY = "captcha";
	public static final String DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME = "securityLoginFailureRetries";
	private String captchaParameter = SPRING_SECURITY_FORM_CAPTCHA_KEY;
	
	private static Logger logger = LoggerFactory.getLogger(UsernamePasswordCaptchaAuthenticationProcessingFilter.class);
	private boolean postOnly = true;
	private final ObjectMapper objectMapper;
	private boolean captchaRequired = false;
	private CaptchaResolver captchaResolver;
	private AuthenticatingFailureCounter failureCounter;
	 private String retryTimesKeyAttribute = DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
	/** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;
	
	// ~ Constructors
	// ===================================================================================================
	
	public UsernamePasswordCaptchaAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super();
		this.objectMapper = objectMapper;
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
		
		try {

			UsernamePasswordAuthenticationToken authRequest = null;
			// Post
			if(WebUtils.isPostRequest(request)) {
				
				PostLoginRequest loginRequest = objectMapper.readValue(request.getReader(), PostLoginRequest.class);
				if (!StringUtils.hasText(loginRequest.getUsername()) || !StringUtils.hasText(loginRequest.getPassword())) {
					throw new AuthenticationServiceException("Username or Password not provided");
				}
				
				// The retry limit has been exceeded and a reminder is required
		        if(isOverRetryRemind(request, response)) {
		        	throw new AuthenticationCaptchaNotFoundException("The number of login errors exceeds the maximum retry limit and a verification code is required.");
		        }
		        
		        // 验证码必填或者错误次数超出系统限制，则要求填入验证码
		 		if(isCaptchaRequired() || isOverRetryTimes(request, response)) {
		 			
		 			if(!StringUtils.hasText(loginRequest.getCaptcha())) {
						throw new AuthenticationCaptchaNotFoundException("Captcha not provided");
					}  
		 	        // 进行验证	
	 	        	boolean validation = captchaResolver.validCaptcha(request, loginRequest.getCaptcha());
					if (!validation) {
						throw new AuthenticationCaptchaIncorrectException("Captcha validation failed!");
					}
					
				}
		 		 
				authRequest = new UsernamePasswordAuthenticationToken( loginRequest.getUsername(), loginRequest.getPassword());

			} else {
				
				// The retry limit has been exceeded and a reminder is required
		        if(isOverRetryRemind(request, response)) {
		        	throw new AuthenticationCaptchaNotFoundException("The number of login errors exceeds the maximum retry limit and a verification code is required.");
		        }
		        // 验证码必填或者错误次数超出系统限制，则要求填入验证码
		 		if(isCaptchaRequired() || isOverRetryTimes(request, response)) {
		 			
		 			String captcha = obtainCaptcha(request);
		 			if(!StringUtils.hasText(captcha)) {
						throw new AuthenticationCaptchaNotFoundException("Captcha not provided");
					}  
		 	        // 进行验证	
	 	        	boolean validation = captchaResolver.validCaptcha(request, captcha);
					if (!validation) {
						throw new AuthenticationCaptchaIncorrectException("Captcha validation failed!");
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
				
		 		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
		            throw new AuthenticationServiceException("Username or Password not provided");
		        }
		 		
		 		authRequest = new UsernamePasswordAuthenticationToken( username, password);
		 		
			}

			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);

		} catch (JsonParseException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (JsonMappingException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (IOException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
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

	protected boolean isOverRetryRemind(ServletRequest request, ServletResponse response) {
		if (null != getFailureCounter() && getFailureCounter().get(request, response, getRetryTimesKeyAttribute()) == getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
	
	protected boolean isOverRetryTimes(ServletRequest request, ServletResponse response) {
		if (null != getFailureCounter() && getFailureCounter().get(request, response, getRetryTimesKeyAttribute()) >= getRetryTimesWhenAccessDenied()) {
			return true;
		}
		return false;
	}
	
	
	public boolean isPostOnly() {
		return postOnly;
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

	public AuthenticatingFailureCounter getFailureCounter() {
		return failureCounter;
	}

	public void setFailureCounter(AuthenticatingFailureCounter failureCounter) {
		this.failureCounter = failureCounter;
	}
	
	public String getRetryTimesKeyAttribute() {
		return retryTimesKeyAttribute;
	}

	public void setRetryTimesKeyAttribute(String retryTimesKeyAttribute) {
		this.retryTimesKeyAttribute = retryTimesKeyAttribute;
	}

	public int getRetryTimesWhenAccessDenied() {
		return retryTimesWhenAccessDenied;
	}

	public void setRetryTimesWhenAccessDenied(int retryTimesWhenAccessDenied) {
		this.retryTimesWhenAccessDenied = retryTimesWhenAccessDenied;
	}

	public ObjectMapper getObjectMapper() {
		return objectMapper;
	}
	
}
