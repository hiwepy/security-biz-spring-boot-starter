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
package org.springframework.security.boot.biz.property.header;

import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Header Content Security Policy Properties
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class HeaderContentSecurityPolicyProperties {

	/**
	 * Enable Security Headers.
	 */
	private boolean enabled = false;

	/**
	 * <p>
	 * Allows configuration for <a href="https://www.w3.org/TR/CSP2/">Content Security Policy (CSP) Level 2</a>.
	 * </p>
	 *
	 * <p>
	 * Calling this method automatically enables (includes) the Content-Security-Policy header in the response
	 * using the supplied security policy directive(s).
	 * </p>
	 *
	 * <p>
	 * Configuration is provided to the {@link ContentSecurityPolicyHeaderWriter} which supports the writing
	 * of the two headers as detailed in the W3C Candidate Recommendation:
	 * </p>
	 * <ul>
	 * 	<li>Content-Security-Policy</li>
	 * 	<li>Content-Security-Policy-Report-Only</li>
	 * </ul>
	 */
	private	String policyDirectives;
	
	/**
	 * Enables (includes) the Content-Security-Policy-Report-Only header in the response.
	 */
	public boolean reportOnly = false;
	

}
