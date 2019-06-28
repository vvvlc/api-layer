/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.apiml.security.handler;

import com.ca.apiml.security.error.AuthMethodNotSupportedException;
import com.ca.apiml.security.error.ErrorType;
import com.ca.apiml.security.token.TokenNotProvidedException;
import com.ca.apiml.security.token.TokenNotValidException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import javax.validation.constraints.NotNull;

@Slf4j
@Component
public class RestResponseHandler {

    public void handleBadResponse(@NotNull Exception exception, @NotNull ErrorType errorType, String genericLogErrorMessage, Object... logParameters) {
        if (exception instanceof RestClientException) {
            HttpClientErrorException hceException = (HttpClientErrorException)exception;
            switch (hceException.getStatusCode()) {
                case UNAUTHORIZED:
                    if (errorType.equals(ErrorType.BAD_CREDENTIALS)) {
                        throw new BadCredentialsException(errorType.getDefaultMessage(), exception);
                    } else if (errorType.equals(ErrorType.TOKEN_NOT_VALID)) {
                        throw new TokenNotValidException(errorType.getDefaultMessage(), exception);
                    } else if (errorType.equals(ErrorType.TOKEN_NOT_PROVIDED)) {
                        throw new TokenNotProvidedException(errorType.getDefaultMessage());
                    } else {
                        throw new BadCredentialsException(ErrorType.BAD_CREDENTIALS.getDefaultMessage(), exception);
                    }
                case BAD_REQUEST:
                    throw new AuthenticationCredentialsNotFoundException(ErrorType.AUTH_CREDENTIALS_NOT_FOUND.getDefaultMessage(), exception);
                case METHOD_NOT_ALLOWED:
                    throw new AuthMethodNotSupportedException(ErrorType.AUTH_METHOD_NOT_SUPPORTED.getDefaultMessage());
                default:
                    addLogMessage(exception, genericLogErrorMessage, logParameters);
                    throw new AuthenticationServiceException(ErrorType.AUTH_GENERAL.getDefaultMessage(), exception);
            }
        }
    }

    private void addLogMessage(Exception exception, String genericLogErrorMessage, Object... logParameters) {
        if (genericLogErrorMessage != null) {
            if (logParameters.length > 0) {
                log.error(genericLogErrorMessage, logParameters);
            } else {
                log.error(genericLogErrorMessage, exception);
            }
        }
    }
}
