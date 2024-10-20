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

import lombok.Data;

/**
 * Security RememberMe Properties
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Data
public class SecurityRememberMeProperties {

	/**
	 * If &lt;tt&gt;true&lt;/tt&gt;, causes any redirection URLs to be calculated minus the protocol
	 * and context path (defaults to &lt;tt&gt;false&lt;/tt&gt;).
	 */
	private boolean contextRelative;
	
}
