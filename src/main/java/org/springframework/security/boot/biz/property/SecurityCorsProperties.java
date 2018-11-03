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

public class SecurityCorsProperties {
	
	/**
	 * Enable Security Cors.
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

	/* Map containing user defined parameters */
	private Map<String, String> customParams = new HashMap<String, String>();
	private Map<String, String> profileAttrs = new HashMap<String, String>();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	private boolean withState;

	private String stateData;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDesc() {
		return desc;
	}

	public void setDesc(String desc) {
		this.desc = desc;
	}

	public String getLogoUrl() {
		return logoUrl;
	}

	public void setLogoUrl(String logoUrl) {
		this.logoUrl = logoUrl;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public boolean isTokenAsHeader() {
		return tokenAsHeader;
	}

	public void setTokenAsHeader(boolean tokenAsHeader) {
		this.tokenAsHeader = tokenAsHeader;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	public boolean isHasGrantType() {
		return hasGrantType;
	}

	public void setHasGrantType(boolean hasGrantType) {
		this.hasGrantType = hasGrantType;
	}

	public Map<String, String> getCustomParams() {
		return customParams;
	}

	public void setCustomParams(Map<String, String> customParams) {
		this.customParams = customParams;
	}

	public Map<String, String> getProfileAttrs() {
		return profileAttrs;
	}

	public void setProfileAttrs(Map<String, String> profileAttrs) {
		this.profileAttrs = profileAttrs;
	}

	public boolean isWithState() {
		return withState;
	}

	public void setWithState(boolean withState) {
		this.withState = withState;
	}

	public String getStateData() {
		return stateData;
	}

	public void setStateData(String stateData) {
		this.stateData = stateData;
	}

}
