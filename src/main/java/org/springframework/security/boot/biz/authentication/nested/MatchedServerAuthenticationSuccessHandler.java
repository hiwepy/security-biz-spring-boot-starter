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
package org.springframework.security.boot.biz.authentication.nested;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;

import reactor.core.publisher.Mono;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public interface MatchedServerAuthenticationSuccessHandler {

	/**
	 * Whether it is supported
	 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
	 * @param authentication  the authentication
	 * @return true or false
	 */
	public boolean supports(Authentication authentication) ;
	
	/**
	 * Invoked when the application authenticates successfully
	 * @param webFilterExchange the exchange
	 * @param authentication the {@link Authentication}
	 * @return a completion notification (success or error)
	 */
	Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
		Authentication authentication);
	
}
