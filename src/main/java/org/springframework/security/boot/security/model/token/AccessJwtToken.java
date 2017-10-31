package io.jsonwebtoken.spring.boot.security.model.token;

import com.alibaba.fastjson.annotation.JSONType;
import com.fasterxml.jackson.annotation.JsonIgnore;

import io.jsonwebtoken.Claims;

/**
 * Raw representation of JWT Token.
 * 
 * @author vladimir.stankovic
 *
 *         May 31, 2016
 */
@JSONType(ignores = {"claims"})
public final class AccessJwtToken implements JwtToken {
    private final String rawToken;
    @JsonIgnore 
    private Claims claims;

    protected AccessJwtToken(final String token, Claims claims) {
        this.rawToken = token;
        this.claims = claims;
    }

    public String getToken() {
        return this.rawToken;
    }

    public Claims getClaims() {
        return claims;
    }
}
