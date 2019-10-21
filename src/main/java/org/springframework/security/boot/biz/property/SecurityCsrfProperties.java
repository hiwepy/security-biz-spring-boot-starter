/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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

import java.util.HashMap;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class SecurityCsrfProperties {

	/**
	 * Enable Security Csrf.
	 */
	private boolean enabled = false;

	private String name;
	private String desc;
	private String logoUrl;

	private String key;

	private String secret;

	private boolean tokenAsHeader;

	private String scope;

	private boolean hasGrantType;
	
	private String ignoringAntMatchers;
	

	/* Map containing user defined parameters */
	private Map<String, String> customParams = new HashMap<String, String>();
	private Map<String, String> profileAttrs = new HashMap<String, String>();

}
