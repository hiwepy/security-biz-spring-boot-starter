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

import org.springframework.security.boot.biz.authentication.AuthenticatingFailureCounter;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationProcessingFilter;

public class SecurityFailureRetryProperties {

	private String retryTimesKeyParameter = AuthenticatingFailureCounter.DEFAULT_RETRY_TIMES_KEY_PARAM_NAME;
	private String retryTimesKeyAttribute = PostRequestAuthenticationProcessingFilter.DEFAULT_RETRY_TIMES_KEY_ATTRIBUTE_NAME;
	/** Maximum number of retry to login . */
	private int retryTimesWhenAccessDenied = 3;

	public String getRetryTimesKeyParameter() {
		return retryTimesKeyParameter;
	}

	public void setRetryTimesKeyParameter(String retryTimesKeyParameter) {
		this.retryTimesKeyParameter = retryTimesKeyParameter;
	}

	public String getRetryTimesKeyAttribute() {
		return retryTimesKeyAttribute;
	}

	public void setRetryTimesKeyAttribute(String retryTimesKeyAttribute) {
		this.retryTimesKeyAttribute = retryTimesKeyAttribute;
	}

	public int getRetryTimesWhenAccessDenied() {
		return retryTimesWhenAccessDenied;
	}

	public void setRetryTimesWhenAccessDenied(int retryTimesWhenAccessDenied) {
		this.retryTimesWhenAccessDenied = retryTimesWhenAccessDenied;
	}
	
}
