/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.gateway.security;

import com.ca.mfaas.security.gateway.*;
import com.ca.mfaas.security.handler.FailedAuthenticationHandler;
import com.ca.mfaas.security.handler.UnauthorizedHandler;
import com.ca.mfaas.security.token.TokenAuthenticationProvider;
import com.ca.mfaas.security.token.TokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@ComponentScan("com.ca.mfaas.security")
@Import(ComponentsConfiguration.class)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private static final String LOGIN_ENDPOINT = "/api/v1/auth/login";
    private static final String QUERY_ENDPOINT = "/api/v1/auth/query";

    private final UnauthorizedHandler unAuthorizedHandler;
    private final GatewaySuccessfulLoginHandler successfulLoginHandler;
    private final GatewaySuccessfulQueryHandler successfulQueryHandler;
    private final FailedAuthenticationHandler authenticationFailureHandler;
    private final SafLoginProvider loginAuthenticationProvider;
    private final TokenAuthenticationProvider tokenAuthenticationProvider;
    private final TokenService tokenService;

    public SecurityConfiguration(
        UnauthorizedHandler unAuthorizedHandler,
        GatewaySuccessfulLoginHandler successfulLoginHandler,
        GatewaySuccessfulQueryHandler successfulQueryHandler,
        FailedAuthenticationHandler authenticationFailureHandler,
        SafLoginProvider loginAuthenticationProvider,
        TokenAuthenticationProvider tokenAuthenticationProvider,
        TokenService tokenService) {
        this.unAuthorizedHandler = unAuthorizedHandler;
        this.successfulLoginHandler = successfulLoginHandler;
        this.successfulQueryHandler = successfulQueryHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
        this.loginAuthenticationProvider = loginAuthenticationProvider;
        this.tokenAuthenticationProvider = tokenAuthenticationProvider;
        this.tokenService = tokenService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(loginAuthenticationProvider);
        auth.authenticationProvider(tokenAuthenticationProvider);
    }

    @Override
    public void configure(WebSecurity web) {
        // skip web filters matchers
        String[] noSecurityAntMatchers = {
            "/",
            "/images/**",
            "/favicon.ico",
        };
        web.ignoring().antMatchers(noSecurityAntMatchers);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .httpBasic().disable()
            .headers().disable()
            .exceptionHandling().authenticationEntryPoint(unAuthorizedHandler)

            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            // login endpoint
            .and()
            .addFilterBefore(loginFilter(LOGIN_ENDPOINT), UsernamePasswordAuthenticationFilter.class)
            .authorizeRequests()

            // query endpoint
            .and()
            .addFilterBefore(queryFilter(QUERY_ENDPOINT), UsernamePasswordAuthenticationFilter.class)
            .authorizeRequests()

            // allow login to pass through filters
            .antMatchers(HttpMethod.POST, LOGIN_ENDPOINT).permitAll();
    }

    private GatewayLoginFilter loginFilter(String loginEndpoint) throws Exception {
        return new GatewayLoginFilter(loginEndpoint, successfulLoginHandler, authenticationFailureHandler, authenticationManager());
    }

    private GatewayQueryFilter queryFilter(String queryEndpoint) throws Exception {
        return new GatewayQueryFilter(queryEndpoint, successfulQueryHandler, authenticationFailureHandler, tokenService,
            authenticationManager());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
