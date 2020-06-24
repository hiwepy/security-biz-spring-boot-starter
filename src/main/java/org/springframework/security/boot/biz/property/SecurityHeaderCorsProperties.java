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

import org.springframework.web.cors.CorsConfiguration;

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
	 * Shortcut to same property on underlying {@link #setUrlPathHelper UrlPathHelper}.
	 * @see org.springframework.web.util.UrlPathHelper#setAlwaysUseFullPath
	 */
	private boolean alwaysUseFullPath = false;
	
	/**
	 * Shortcut to same property on underlying {@link #setUrlPathHelper UrlPathHelper}.
	 * @see org.springframework.web.util.UrlPathHelper#setUrlDecode
	 */
	private boolean urlDecode = false;
	
	/**
	 * Shortcut to same property on underlying {@link #setUrlPathHelper UrlPathHelper}.
	 * @see org.springframework.web.util.UrlPathHelper#setRemoveSemicolonContent(boolean)
	 */
	private boolean removeSemicolonContent = false;
	
	/**
	 * Set CORS configuration based on URL patterns.
	 */
	private  Map<String, CorsConfiguration> corsConfigurations;
	
}
