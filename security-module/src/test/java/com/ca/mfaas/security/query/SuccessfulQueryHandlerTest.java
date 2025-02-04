/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.security.query;

import com.ca.mfaas.security.config.SecurityConfigurationProperties;
import com.ca.mfaas.security.token.JwtSecurityInitializer;
import com.ca.mfaas.security.token.TokenAuthentication;
import com.ca.mfaas.security.token.TokenService;
import com.ca.mfaas.security.SecurityUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SuccessfulQueryHandlerTest {

    @Test
    public void successfulLoginHandlerTestForCookie() throws IOException {
        String user = "user";
        String domain = "domain";
        String ltpa = "ltpa";
        SignatureAlgorithm algorithm = SignatureAlgorithm.RS256;
        KeyPair keyPair = SecurityUtils.generateKeyPair("RSA", 2048);
        Key privateKey = null;
        PublicKey publicKey = null;
        if (keyPair != null) {
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        }

        SecurityConfigurationProperties securityConfigurationProperties = new SecurityConfigurationProperties();
        JwtSecurityInitializer jwtSecurityInitializer = mock(JwtSecurityInitializer.class);
        TokenService tokenService = new TokenService(securityConfigurationProperties, jwtSecurityInitializer);

        when(jwtSecurityInitializer.getSignatureAlgorithm()).thenReturn(algorithm);
        when(jwtSecurityInitializer.getJwtSecret()).thenReturn(privateKey);
        when(jwtSecurityInitializer.getJwtPublicKey()).thenReturn(publicKey);

        ObjectMapper mapper = new ObjectMapper();
        SuccessfulQueryHandler successfulQueryHandler = new SuccessfulQueryHandler(mapper, tokenService);

        String token = tokenService.createToken(user, domain, ltpa);
        TokenAuthentication tokenAuthentication = new TokenAuthentication(user, token);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        successfulQueryHandler.onAuthenticationSuccess(request, response, tokenAuthentication);

        assertEquals(HttpStatus.OK.value(), response.getStatus());
        assertEquals(MediaType.APPLICATION_JSON_UTF8_VALUE, response.getContentType());
        assertTrue(response.getContentAsString().contains("{\"domain\":\"domain\",\"userId\":\"user\",\"creation\":"));
    }
}
