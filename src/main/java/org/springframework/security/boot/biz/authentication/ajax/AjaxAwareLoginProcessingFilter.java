package org.springframework.security.boot.biz.authentication.ajax;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.exception.AuthMethodNotSupportedException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @className	： AjaxUsernamePasswordAuthenticationFilter
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2018年3月7日 下午2:05:58
 * @version 	V1.0
 */
public class AjaxAwareLoginProcessingFilter extends UsernamePasswordAuthenticationFilter {
	
    private static Logger logger = LoggerFactory.getLogger(AjaxAwareLoginProcessingFilter.class);
    
    // ~ Constructors
 	// ===================================================================================================

 	public AjaxAwareLoginProcessingFilter() {
 		super();
 	}
 	
 	// ~ Methods
 	// ========================================================================================================

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
    	
    	 if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtils.isAjaxRequest(request)) {
             if(logger.isDebugEnabled()) {
                 logger.debug("Authentication method not supported. Request method: " + request.getMethod());
             }
             throw new AuthMethodNotSupportedException(
 					"Authentication method not supported: " + request.getMethod());
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

 		if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
            throw new AuthenticationServiceException("Username or Password not provided");
        }
 		
 		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
 				username, password);

 		// Allow subclasses to set the "details" property
 		setDetails(request, authRequest);

 		return this.getAuthenticationManager().authenticate(authRequest);
    }
    
}
