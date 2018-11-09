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

import com.ca.mfaas.security.login.InvalidUserException;
import com.ca.mfaas.security.token.TokenAuthentication;
import com.ca.mfaas.security.token.TokenService;
import com.ibm.os390.security.PlatformReturned;
import com.ibm.os390.security.PlatformSecurityServer;
import com.ibm.os390.security.PlatformUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class SafLoginProvider implements AuthenticationProvider {
    private final TokenService tokenService;

    public SafLoginProvider(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        String userId = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();


        if(PlatformSecurityServer.isActive()) {
            log.debug("Server is running.");
        }

        PlatformReturned pr = PlatformUser.authenticate(userId, password);

        if (pr != null) {
            log.debug("SAF ERROR {}: success = {}\n    errno = {}\n    errno2 = {}\n    errnoMsg = {}\n    stringRet = {}\n    objectRet = {}",
                pr.success, pr.errno, pr.errno2, pr.errnoMsg, pr.stringRet, pr.objectRet);
            throw new InvalidUserException("Username or password are invalid.");
        }

        String jwtToken = tokenService.createToken(userId, "SAF", "");
        TokenAuthentication tokenAuthentication = new TokenAuthentication(userId, jwtToken);
        tokenAuthentication.setAuthenticated(true);

        return tokenAuthentication;
    }

    @Override
    public boolean supports(Class<?> auth) {
        return auth.equals(UsernamePasswordAuthenticationToken.class);
    }
}
