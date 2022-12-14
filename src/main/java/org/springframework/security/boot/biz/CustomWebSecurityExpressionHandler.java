package org.springframework.security.boot.biz;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

public class CustomWebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private String defaultRolePrefix = "ROLE_";

    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
        WebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, fi) ;
        System.out.println("=================================" + fi.getRequest().getRemoteAddr());
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(this.trustResolver);
        root.setRoleHierarchy(this.getRoleHierarchy());
        root.setDefaultRolePrefix(this.defaultRolePrefix);
        return root;
    }

    @Override
    public void setTrustResolver(AuthenticationTrustResolver trustResolver){
        super.setTrustResolver(trustResolver);
        this.trustResolver = trustResolver;
    }

    @Override
    public void setDefaultRolePrefix(String defaultRolePrefix) {
        super.setDefaultRolePrefix(defaultRolePrefix);
        this.defaultRolePrefix = defaultRolePrefix;
    }

}