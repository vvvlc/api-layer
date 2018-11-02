/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.security.token;

import com.ca.mfaas.product.config.MFaaSConfigPropertiesContainer;
import com.ca.mfaas.security.gateway.GatewayQueryResponse;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import java.util.Date;
import java.util.UUID;

@Service
@Slf4j
public class TokenService {
    private static final String BEARER_HEADER = "Bearer ";

    private final MFaaSConfigPropertiesContainer propertiesContainer;

    public TokenService(MFaaSConfigPropertiesContainer propertiesContainer) {
        this.propertiesContainer = propertiesContainer;
    }

    public String createToken(String username, String domain, String ltpaToken) {
        long now = System.currentTimeMillis();
        long expiration = calculateExpiration(now, username);

        return Jwts.builder()
            .setSubject(username)
            .claim("dom", domain)
            .claim("ltpa", ltpaToken)
            .setIssuedAt(new Date(now))
            .setExpiration(new Date(expiration))
            .setIssuer(propertiesContainer.getSecurity().getTokenProperties().getIssuer())
            .setId(UUID.randomUUID().toString())
            .signWith(SignatureAlgorithm.HS512, propertiesContainer.getSecurity().getTokenProperties().getSecret())
            .compact();
    }

    TokenAuthentication validateToken(TokenAuthentication token) {
        try {
            Claims claims = Jwts.parser()
                .setSigningKey(propertiesContainer.getSecurity().getTokenProperties().getSecret())
                .parseClaimsJws(token.getCredentials())
                .getBody();

            claims.getExpiration();
            String username = claims.getSubject();
            TokenAuthentication validTokenAuthentication = new TokenAuthentication(username, token.getCredentials());
            validTokenAuthentication.setAuthenticated(true);
            return validTokenAuthentication;
        } catch (ExpiredJwtException exception) {
            log.debug("Token with id '{}' for user '{}' is expired", exception.getClaims().getId(), exception.getClaims().getSubject());
            throw new TokenExpireException("Token is expired");
        } catch (JwtException exception) {
            log.debug("Token is not valid due to: {}", exception.getMessage());
            throw new TokenNotValidException("Token is not valid");
        } catch (Exception exception) {
            log.debug("Token is not valid due to: {}", exception.getMessage());
            throw new TokenNotValidException("An internal error occurred while validating the token therefor the token is no longer valid");
        }
    }

    public GatewayQueryResponse parseToken(String token) {
        Claims claims = Jwts.parser()
            .setSigningKey(propertiesContainer.getSecurity().getTokenProperties().getSecret())
            .parseClaimsJws(token)
            .getBody();

        return new GatewayQueryResponse(claims.get("dom", String.class),
            claims.getSubject(), claims.getIssuedAt(), claims.getExpiration());
    }

    public String getLtpaToken(String jwtToken) {
        Claims claims = Jwts.parser()
            .setSigningKey(propertiesContainer.getSecurity().getTokenProperties().getSecret())
            .parseClaimsJws(jwtToken)
            .getBody();

        return claims.get("ltpa", String.class);
    }

    public String getToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(propertiesContainer.getSecurity().getCookieProperties().getCookieName())) {
                    return cookie.getValue();
                }
            }
        }

        return extractToken(request.getHeader(HttpHeaders.AUTHORIZATION));
    }

    private String extractToken(String header) {
        if (header != null && header.startsWith(BEARER_HEADER)) {
            return header.replaceFirst(BEARER_HEADER, "");
        }

        return null;
    }

    private long calculateExpiration(long now, String username) {
        long expiration = now + (propertiesContainer.getSecurity().getTokenProperties().getExpirationInSeconds() * 1000);

        // calculate time for short TTL user
        if (propertiesContainer.getSecurity().getTokenProperties().getShortTtlUsername() != null) {
            if (username.equals(propertiesContainer.getSecurity().getTokenProperties().getShortTtlUsername())) {
                expiration = now + (propertiesContainer.getSecurity().getTokenProperties().getShortTtlExpirationInSeconds() * 1000);
            }
        }
        return expiration;
    }
}
