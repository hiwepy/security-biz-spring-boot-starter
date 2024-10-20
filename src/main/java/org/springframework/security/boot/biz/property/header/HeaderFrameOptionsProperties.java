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
package org.springframework.security.boot.biz.property.header;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * Header Frame Options Properties
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class HeaderFrameOptionsProperties {

	/**
	 * Enable Security Headers.
	 */
	private boolean enabled = false;
	/**
	 * Specify to DENY framing any content from this application.
	 */
	private boolean deny = false;
	/**
	 * Specify to allow any request that comes from the same origin to frame this
	 * application. For example, if the application was hosted on example.com, then
	 * example.com could frame the application, but evil.com could not frame the
	 * application.
	 */
	private boolean sameOrigin = false;
	private boolean allowFrom = false;

}
