/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

import com.github.vindell.jwt.JwtPayload;

/**
 * Abstract JSON Web Token (JWT) Payload Repository
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public abstract class JwtPayloadRepository {

	public abstract String issueJwt(AbstractAuthenticationToken token);

	public abstract boolean verify(AbstractAuthenticationToken token, boolean checkExpiry) throws AuthenticationException;

	public abstract JwtPayload getPayload(AbstractAuthenticationToken token, boolean checkExpiry);

}
