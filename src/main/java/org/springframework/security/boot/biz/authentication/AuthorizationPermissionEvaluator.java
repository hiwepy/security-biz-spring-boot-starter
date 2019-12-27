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

import java.io.Serializable;
import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * TODO
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */

public class AuthorizationPermissionEvaluator implements PermissionEvaluator {

	@Override
	public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
		if (StringUtils.equalsIgnoreCase("*", permission.toString())) {
			return true;
		}
		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		for (GrantedAuthority authority : authorities) {
			if (authority.getAuthority().equals(permission)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	   *  简单的字符串比较，相同则认为有权限
	 */
	@Override
	public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
			Object permission) {
		if (StringUtils.equalsIgnoreCase("*", permission.toString())) {
			return true;
		}
		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		for (GrantedAuthority authority : authorities) {
			if (authority.getAuthority().equals(permission)) {
				return true;
			}
		}
		return false;
	}
	
	public boolean hasPermission(Object permission) {
		if (StringUtils.equalsIgnoreCase("*", permission.toString())) {
			return true;
		}
		Collection<? extends GrantedAuthority> authorities = SubjectUtils.getAuthentication().getAuthorities();
		for (GrantedAuthority authority : authorities) {
			if (authority.getAuthority().equals(permission)) {
				return true;
			}
		}
		return false;
	}

}
