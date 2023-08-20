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
import org.springframework.security.web.header.writers.FeaturePolicyHeaderWriter;

/**
 * Header Feature Policy Properties
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class HeaderFeaturePolicyProperties {

	/**
	 * Enable Security Headers.
	 */
	private boolean enabled = false;
	
	/**
	 * Allows configuration for <a href="https://wicg.github.io/feature-policy/">Feature
	 * Policy</a>.
	 * <p>
	 * Calling this method automatically enables (includes) the {@code Feature-Policy}
	 * header in the response using the supplied policy directive(s).
	 * <p>
	 * Configuration is provided to the {@link FeaturePolicyHeaderWriter} which is responsible for writing the header.
	 */
	private String policyDirectives;

}
