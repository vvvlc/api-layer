/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.apicatalog.gateway;

/**
 * Exception thrown when there's need to interrupt {@link GatewayLookupService} retry process
 */
public class GatewayLookupException extends RuntimeException {
    private static final long serialVersionUID = -559112794280136165L;

    public GatewayLookupException(String message) {
        super(message);
    }

    public GatewayLookupException(String message, Throwable cause) {
        super(message, cause);
    }
}
