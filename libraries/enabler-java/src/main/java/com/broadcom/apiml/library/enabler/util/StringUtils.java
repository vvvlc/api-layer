/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.broadcom.apiml.library.enabler.util;

public class StringUtils {
    private StringUtils() {
    }

    public static boolean isNullOrEmpty(String string) {
        boolean result = false;
        if (string == null || string.trim().isEmpty()) {
            result = true;
        }
        return result;
    }
}
