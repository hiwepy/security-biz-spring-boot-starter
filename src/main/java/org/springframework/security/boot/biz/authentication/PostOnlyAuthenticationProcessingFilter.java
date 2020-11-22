package org.springframework.security.boot.biz.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationMethodNotSupportedException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * PostOnly Authentication Processing Filter
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public abstract class PostOnlyAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	public static final String DEFAULT_LONGITUDE_LATITUDE = "0.000000";
	
	/**
	 * HTTP Authorization header, equal to <code>X-Sign</code>
	 */
	public static final String SIGN_HEADER = "X-Sign";
	/**
	 * HTTP Authorization header, equal to <code>X-Longitude</code>
	 */
	public static final String LONGITUDE_HEADER = "X-Longitude";
	/**
	 * HTTP Authorization header, equal to <code>X-Latitude</code>
	 */
	public static final String LATITUDE_HEADER = "X-Latitude";
	/**
	 * HTTP Authorization header, equal to <code>X-X-APP-ID</code>
	 */
	public static final String APP_ID_HEADER = "X-APP-ID";
	/**
	 * HTTP Authorization header, equal to <code>X-APP-CHANNEL</code>
	 */
	public static final String APP_CHANNEL_HEADER = "X-APP-CHANNEL";

	/**
	 * HTTP Authorization header, equal to <code>X-APP-VERSION</code>
	 */
	public static final String APP_VERSION_HEADER = "X-APP-VERSION";
	
	private String signHeaderName = SIGN_HEADER;
	private String longitudeHeaderName = LONGITUDE_HEADER;
	private String latitudeHeaderName = LATITUDE_HEADER;
	private String appIdHeaderName = APP_ID_HEADER;
	private String appChannelHeaderName = APP_CHANNEL_HEADER;
	private String appVersionHeaderName = APP_VERSION_HEADER;
	
	// ~ Static fields/initializers
	// =====================================================================================
	
	protected static Logger logger = LoggerFactory.getLogger(PostOnlyAuthenticationProcessingFilter.class);
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private boolean postOnly = true;
	
	// ~ Constructors
	// ===================================================================================================
	
	/**
	 * @param defaultFilterProcessesUrl the default value for <tt>filterProcessesUrl</tt>.
	 */
	protected PostOnlyAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	/**
	 * Creates a new instance
	 *
	 * @param requiresAuthenticationRequestMatcher the {@link RequestMatcher} used to
	 * determine if authentication is required. Cannot be null.
	 */
	protected PostOnlyAuthenticationProcessingFilter(
			RequestMatcher requiresAuthenticationRequestMatcher) {
		super(requiresAuthenticationRequestMatcher);
	}

	// ~ Methods
	// ========================================================================================================

	@Override
	public final Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		if (isPostOnly() && !WebUtils.isPostRequest(request) ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not supported. Request method: " + request.getMethod());
			}
			throw new AuthenticationMethodNotSupportedException(messages.getMessage(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(), new Object[] { request.getMethod() }, 
					"Authentication method not supported. Request method:" + request.getMethod()));
		}
		
		// Set RequestContextHolder
		ServletRequestAttributes requestAttributes = new ServletRequestAttributes(request, response);
		RequestContextHolder.setRequestAttributes(requestAttributes, true);
		
		// real method
		return this.doAttemptAuthentication(request, response);

	}
	

	/**
	 * Performs actual authentication.
	 * <p>
	 * The implementation should do one of the following:
	 * <ol>
	 * <li>Return a populated authentication token for the authenticated user, indicating
	 * successful authentication</li>
	 * <li>Return null, indicating that the authentication process is still in progress.
	 * Before returning, the implementation should perform any additional work required to
	 * complete the process.</li>
	 * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
	 * </ol>
	 *
	 * @param request from which to extract parameters and perform the authentication
	 * @param response the response, which may be needed if the implementation has to do a
	 * redirect as part of a multi-stage authentication process (such as OpenID).
	 *
	 * @return the authenticated user token, or null if authentication is incomplete.
	 *
	 * @throws AuthenticationException if authentication fails.
	 */
	public abstract Authentication doAttemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException, IOException,
			ServletException;
 
	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If set to
	 * true, and an authentication request is received which is not a POST request, an
	 * exception will be raised immediately and authentication will not be attempted. The
	 * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
	 * authentication.
	 * <p>
	 * Defaults to <tt>true</tt> but may be overridden by subclasses.
	 * @param postOnly if postOnly
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}
	
	public boolean isPostOnly() {
		return postOnly;
	}
	
	protected double obtainLongitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLongitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	protected double obtainLatitude(HttpServletRequest request) {
		return Double.parseDouble(StringUtils.defaultIfBlank(request.getHeader(getLatitudeHeaderName()), DEFAULT_LONGITUDE_LATITUDE));
	}
	
	protected String obtainSign(HttpServletRequest request) {
		return request.getHeader(getSignHeaderName());
	}
	
	protected String obtainAppId(HttpServletRequest request) {
		String appId = request.getHeader(getAppIdHeaderName());
		logger.debug(APP_ID_HEADER + "：{}", appId);
		return appId;
	}
	
	protected String obtainAppChannel(HttpServletRequest request) {
		String appChannel = request.getHeader(getAppChannelHeaderName());
		logger.debug(APP_CHANNEL_HEADER + "：{}", appChannel);
		return appChannel;
	}
	
	protected String obtainAppVersion(HttpServletRequest request) {
		String appVersion = request.getHeader(getAppVersionHeaderName());
		logger.debug(APP_VERSION_HEADER + "：{}", appVersion);
		return appVersion;
	}
	
	public String getSignHeaderName() {
		return signHeaderName;
	}

	public void setSignHeaderName(String signHeaderName) {
		this.signHeaderName = signHeaderName;
	}

	public String getLongitudeHeaderName() {
		return longitudeHeaderName;
	}

	public void setLongitudeHeaderName(String longitudeHeaderName) {
		this.longitudeHeaderName = longitudeHeaderName;
	}

	public String getLatitudeHeaderName() {
		return latitudeHeaderName;
	}

	public void setLatitudeHeaderName(String latitudeHeaderName) {
		this.latitudeHeaderName = latitudeHeaderName;
	}

	public String getAppIdHeaderName() {
		return appIdHeaderName;
	}

	public void setAppIdHeaderName(String appIdHeaderName) {
		this.appIdHeaderName = appIdHeaderName;
	}

	public String getAppChannelHeaderName() {
		return appChannelHeaderName;
	}

	public void setAppChannelHeaderName(String appChannelHeaderName) {
		this.appChannelHeaderName = appChannelHeaderName;
	}

	public String getAppVersionHeaderName() {
		return appVersionHeaderName;
	}

	public void setAppVersionHeaderName(String appVersionHeaderName) {
		this.appVersionHeaderName = appVersionHeaderName;
	}
	
}