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
package org.springframework.security.boot.biz.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * An {@code AuthenticationListener} listens for notifications while authenticate with the system.
 */
public interface AuthenticationListener {

    /**
    /**
	 * Calls the parent class {@code handle()} method to forward or redirect to the target
	 * URL, and then calls {@code clearAuthenticationAttributes()} to remove any leftover
	 * session data.
     *
     * @param request that resulted in an <code>AuthenticationException</code>
     * @param response so that the user agent can begin authentication
     * @param authentication the {@code Authentication} that occurred as a result of the attempt.
     */
    void onSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication);

    /**
     * Callback triggered when an authentication attempt for a {@code Subject} has failed.
     *
     * @param request that resulted in an <code>AuthenticationException</code>
     * @param response so that the user agent can begin authentication
     * @param ae    the {@code AuthenticationException} that occurred as a result of the attempt.
     */
    void onFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException ae);
    
}
