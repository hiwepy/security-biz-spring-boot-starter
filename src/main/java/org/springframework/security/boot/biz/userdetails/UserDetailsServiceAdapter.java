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
package org.springframework.security.boot.biz.userdetails;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public abstract class UserDetailsServiceAdapter implements UserDetailsService, UserDetailsPasswordService, AuthenticationUserDetailsService<Authentication> {

	@Override
	public UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException {
		if(token.getPrincipal() instanceof String) {
			return this.loadUserByUsername(String.valueOf(token.getPrincipal()));
		}
		return null;
	}

	public UserDetails loadUserDetailsWithSave(Authentication token) throws UsernameNotFoundException {
		return null;
	}
	
	public UserDetails loadUserDetails(String userid) throws UsernameNotFoundException {
		return null;
	}
	
	public UserDetails loadUserDetails(String userId, String roleId) throws UsernameNotFoundException {
		return null;
	}
	
	public UserDetails loadUserDetailsWithoutPwd(String username) throws UsernameNotFoundException {
		return null;
	}
	
	
	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		return null;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.loadUserDetailsWithoutPwd(username);
	}

}
