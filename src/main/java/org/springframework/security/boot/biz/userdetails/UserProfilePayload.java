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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import lombok.Data;

@Data
public class UserProfilePayload {
	
	/**
	 * 用户ID（用户来源表Id）
	 */
	private String uid;
	/**
	 * 用户UUID（用户唯一ID）
	 */
	private String uuid;
	/**
	 * 用户Key：用户业务表中的唯一ID
	 */
	private String ukey;
	/**
	 * 用户Code：用户业务表中的唯一编码
	 */
	private String ucode;
	/**
	 * 角色ID（角色表Id）
	 */
	private String rid;
	/**
	 * 角色Key：角色业务表中的唯一ID
	 */
	private String rkey;
	/**
	 * 角色Code：角色业务表中的唯一编码
	 */
	private String rcode;
	/**
	 * JWT Token
	 */
	private String token;
	/**
   	 * 用户是否绑定信息
   	 */
    private boolean bound = Boolean.FALSE;
    /**
   	 * 用户是否完善信息
   	 */
    private boolean initial = Boolean.FALSE;
    /**
	 * User Profile
	 */
    private Map<String, Object> profile = new HashMap<>();
	/**
	 * User Roles
	 */
    private Set<String> roles = new HashSet<>();
    /**
	 * 用户权限标记列表
	 */
	private Set<String> perms = new HashSet<>();

}
