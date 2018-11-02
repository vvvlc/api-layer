/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.security.gateway;

import com.ca.mfaas.product.config.MFaaSConfigPropertiesContainer;
import com.ca.mfaas.security.token.TokenAuthentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class GatewaySuccessfulLoginHandler implements AuthenticationSuccessHandler {
    private final MFaaSConfigPropertiesContainer propertiesContainer;

    public GatewaySuccessfulLoginHandler(MFaaSConfigPropertiesContainer propertiesContainer) {
        this.propertiesContainer = propertiesContainer;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        TokenAuthentication tokenAuthentication = (TokenAuthentication) authentication;
        String token = tokenAuthentication.getCredentials();

        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setStatus(HttpStatus.OK.value());
        setCookie(token, response);
    }

    /**
     * Add the cookie to the response
     *
     * @param token    the authentication token
     * @param response send back this response
     */
    private void setCookie(String token, HttpServletResponse response) {
        Cookie tokenCookie = new Cookie(propertiesContainer.getSecurity().getCookieProperties().getCookieName(), token);
        tokenCookie.setComment(propertiesContainer.getSecurity().getCookieProperties().getCookieComment());
        tokenCookie.setPath(propertiesContainer.getSecurity().getCookieProperties().getCookiePath());
        tokenCookie.setHttpOnly(true);
        tokenCookie.setMaxAge(propertiesContainer.getSecurity().getCookieProperties().getCookieMaxAge());
        tokenCookie.setSecure(propertiesContainer.getSecurity().getCookieProperties().isCookieSecure());
        response.addCookie(tokenCookie);
    }
}
