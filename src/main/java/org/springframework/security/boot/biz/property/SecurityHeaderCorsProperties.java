/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.biz.property;

import java.util.Map;

import org.springframework.util.PathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.UrlPathHelper;
import org.springframework.web.util.pattern.PathPattern;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Security Header Cors Properties
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class SecurityHeaderCorsProperties {

	/** Wildcard representing <em>all</em> origins, methods, or headers. */
	public static final String ALL = "*";
	
	/**
	 * Enable Security Cros.
	 */
	private boolean enabled = false;

	/**
	  * When enabled, if there is neither a
	 * {@link UrlPathHelper#resolveAndCacheLookupPath esolved} String lookupPath nor a
	 * {@link ServletRequestPathUtils#parseAndCache parsed} {@code RequestPath}
	 * then use the {@link #setUrlPathHelper configured} {@code UrlPathHelper}
	 * to resolve a String lookupPath. This in turn determines use of URL
	 * pattern matching with {@link PathMatcher} or with parsed {@link PathPattern}s.
	 * <p>In Spring MVC, either a resolved String lookupPath or a parsed
	 * {@code RequestPath} is always available within {@code DispatcherServlet}
	 * processing. However in a Servlet {@code Filter} such as {@code CorsFilter}
	 * that may or may not be the case.
	 * <p>By default this is set to {@code true} in which case lazy lookupPath
	 * initialization is allowed. Set this to {@code false} when an
	 * application is using parsed {@code PathPatterns} in which case the
	 * {@code RequestPath} can be parsed earlier via
	 * {@link org.springframework.web.filter.ServletRequestPathFilter
	 * ServletRequestPathFilter}.
	 */
	private boolean allowInitLookupPath = true;

	/**
	 * Shortcut to same property on underlying {@link #setUrlPathHelper UrlPathHelper}.
	 * @see org.springframework.web.util.UrlPathHelper#setAlwaysUseFullPath
	 */
	@Deprecated
	private boolean alwaysUseFullPath = false;
	
	/**
	 * Shortcut to same property on underlying {@link #setUrlPathHelper UrlPathHelper}.
	 * @see org.springframework.web.util.UrlPathHelper#setUrlDecode
	 */
	@Deprecated
	private boolean urlDecode = false;
	
	/**
	 * Shortcut to same property on underlying {@link #setUrlPathHelper UrlPathHelper}.
	 * @see org.springframework.web.util.UrlPathHelper#setRemoveSemicolonContent(boolean)
	 */
	@Deprecated
	private boolean removeSemicolonContent = false;
	
	/**
	 * Set CORS configuration based on URL patterns.
	 */
	private  Map<String, CorsConfiguration> corsConfigurations;
	
}
