/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
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
package org.springframework.security.boot.biz.authentication.captcha;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface CaptchaResolver {

	/**
	 * Valid the current captcha via the given request.
	 * @param request request to be used for resolution
	 * @return the result
	 */
	boolean validCaptcha(HttpServletRequest request, String capText);

	/**
	 * Set the current captcha to the given one.
	 * @param request request to be used for captcha modification
	 * @param response response to be used for captcha modification
	 * @param capText the new captcha value
	 * @throws UnsupportedOperationException if the CaptchaResolver implementation does not support dynamic changing of the captcha
	 */
	void setCaptcha(HttpServletRequest request, HttpServletResponse response, String capText, Date capDate);
	
}
