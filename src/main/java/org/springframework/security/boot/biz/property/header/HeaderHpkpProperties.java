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

import java.util.HashMap;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class HeaderHpkpProperties {

	/**
	 * Enable Security Headers.
	 */
	private boolean enabled = false;

	/**
	 * <p>
	 * If true, the pinning policy applies to this pinned host as well as any subdomains
	 * of the host's domain name. The default is false.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.3">Section 2.1.3</a>
	 * for additional details.
	 * </p>
	 */
	private boolean includeSubDomains;
	
	/**
	 * 
	 * The maximum amount of time (in seconds) to regard the host
	 * 
	 * <p>
	 * Sets the value (in seconds) for the max-age directive of the Public-Key-Pins header. The default is 60 days.
	 * </p>
	 *
	 * <p>
	 * This instructs browsers how long they should regard the host (from whom the message was received)
	 * as a known pinned host. See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.2">Section
	 * 2.1.2</a> for additional details.
	 * </p>
	 */
	private long maxAgeInSeconds;
	
	/**
	 * <p>
	 * If true, the browser should not terminate the connection with the server. The default is true.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1">Section 2.1</a>
	 * for additional details.
	 * </p>
	 *
	 * true to report only, else false
	 */
	private boolean reportOnly = true;
	
	/**
	 * 
	 * The URI where the browser should send the report to.
	 * 
	 * <p>
	 * Sets the URI to which the browser should report pin validation failures.
	 * </p>
	 *
	 * <p>
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.4">Section 2.1.4</a>
	 * for additional details.
	 * </p>
	 */
	private String reportUri;
	
	/**
	 * <p>
	 * Adds a list of SHA256 hashed pins for the pin- directive of the Public-Key-Pins header.
	 * </p>
	 *
	 * <p>
	 * The pin directive specifies a way for web host operators to indicate
	 * a cryptographic identity that should be bound to a given web host.
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.1">Section 2.1.1</a> for additional details.
	 * </p>
	 *
	 * A list of base64-encoded SPKI fingerprints.
	 */
	private String[] sha256Pins = new String[0];
	
	/**
	 * pins the map of base64-encoded SPKI fingerprint &amp; cryptographic hash algorithm pairs.
	 * 
	 * <p>
	 * Sets the value for the pin- directive of the Public-Key-Pins header.
	 * </p>
	 *
	 * <p>
	 * The pin directive specifies a way for web host operators to indicate
	 * a cryptographic identity that should be bound to a given web host.
	 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.1">Section 2.1.1</a> for additional details.
	 * </p>
	 */
	private Map<String, String> pins = new HashMap<String, String>();

}
