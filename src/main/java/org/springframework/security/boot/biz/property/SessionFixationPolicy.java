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

import jakarta.servlet.http.HttpSession;

/**
 * Session Fixation Policy 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public enum SessionFixationPolicy {

	/**
	 * Specifies that the Servlet container-provided session fixation protection
	 * should be used. When a session authenticates, the Servlet 3.1 method
	 * {@code HttpServletRequest#changeSessionId()} is called to change the session
	 * ID and retain all session attributes. Using this option in a Servlet 3.0 or
	 * older container results in an {@link IllegalStateException}.
	 */
	CHANGE_SESSION_ID,
	/**
	 * Specifies that a new session should be created and the session attributes
	 * from the original {@link HttpSession} should be retained.
	 */
	MIGRATE_SESSION,
	/**
	 * Specifies that a new session should be created, but the session attributes
	 * from the original {@link HttpSession} should not be retained.
	 */
	NEW_SESSION,
	/**
	 * Specifies that no session fixation protection should be enabled. This may be
	 * useful when utilizing other mechanisms for protecting against session
	 * fixation. For example, if application container session fixation protection
	 * is already in use. Otherwise, this option is not recommended.
	 */
	NONE;
	
	public boolean equals(SessionFixationPolicy policy) {
		return this.compareTo(policy) == 0;
	}

}
