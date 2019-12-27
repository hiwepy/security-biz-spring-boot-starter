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

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class HeaderHstsProperties {

	/**
	 * Enable Security Headers.
	 */
	private boolean enabled = false;

	/**
	 * <p>
	 * If true, subdomains should be considered HSTS Hosts too. The default is true.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc6797#section-6.1.2">Section
	 * 6.1.2</a> for additional details.
	 * </p>
	 */
	private boolean includeSubDomains;
	
	/**
	 * The maximum amount of time (in seconds) to consider this domain as a known HSTS Host.
	 * <p>
	 * Sets the value (in seconds) for the max-age directive of the Strict-Transport-Security header. The default is one year.
	 * </p>
	 *
	 * <p>
	 * This instructs browsers how long to remember to keep this domain as a known
	 * HSTS Host. See <a
	 * href="https://tools.ietf.org/html/rfc6797#section-6.1.1">Section 6.1.1</a> for
	 * additional details.
	 * </p>
	 */
	private long maxAgeInSeconds;

}
