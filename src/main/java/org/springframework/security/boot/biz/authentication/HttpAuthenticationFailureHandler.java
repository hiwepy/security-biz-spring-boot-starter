package org.springframework.security.boot.biz.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.boot.biz.exception.AuthMethodNotSupportedException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @className	： RestAuthenticationFailureHandler
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2018年3月10日 下午11:41:10
 * @version 	V1.0
 */
public class HttpAuthenticationFailureHandler implements AuthenticationFailureHandler {
   
	private static final Logger logger = LoggerFactory.getLogger(HttpAuthenticationFailureHandler.class);
	
	private PortMapper portMapper = new PortMapperImpl();
	private PortResolver portResolver = new PortResolverImpl();
    private String failureUrl;
	private boolean forceHttps = false;
	private final ObjectMapper mapper;
	
    public HttpAuthenticationFailureHandler(final ObjectMapper mapper, final String failureUrl) {
        this.mapper = mapper;
        this.failureUrl = failureUrl;
    }
    
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		
		/*
		 * if Rest request return 401 Unauthorized else rediect to specific page
		 */
		if (WebUtils.isPostRequest(request)) {
			
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			
			if (e instanceof BadCredentialsException) {
				mapper.writeValue(response.getWriter(), HttpErrorResponse.of("Invalid username or password", HttpStatus.UNAUTHORIZED));
			} else if (e instanceof AuthMethodNotSupportedException) {
			    mapper.writeValue(response.getWriter(), HttpErrorResponse.of(e.getMessage(), HttpStatus.UNAUTHORIZED));
			}

			mapper.writeValue(response.getWriter(), HttpErrorResponse.of("Authentication failed", HttpStatus.UNAUTHORIZED));
			
		} else {
			response.sendRedirect(buildRedirectUrlToLoginPage(request, response, e));
		}
		
	}
	
	protected String buildRedirectUrlToLoginPage(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException authException) {

		if (UrlUtils.isAbsoluteUrl(failureUrl)) {
			return failureUrl;
		}

		int serverPort = portResolver.getServerPort(request);
		String scheme = request.getScheme();

		RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();

		urlBuilder.setScheme(scheme);
		urlBuilder.setServerName(request.getServerName());
		urlBuilder.setPort(serverPort);
		urlBuilder.setContextPath(request.getContextPath());
		urlBuilder.setPathInfo(failureUrl);

		if (forceHttps && "http".equals(scheme)) {
			Integer httpsPort = portMapper.lookupHttpsPort(Integer.valueOf(serverPort));

			if (httpsPort != null) {
				// Overwrite scheme and port in the redirect URL
				urlBuilder.setScheme("https");
				urlBuilder.setPort(httpsPort.intValue());
			}
			else {
				logger.warn("Unable to redirect to HTTPS as no port mapping found for HTTP port "
						+ serverPort);
			}
		}

		return urlBuilder.getUrl();
	}

}
