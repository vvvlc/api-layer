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

import org.junit.Test;

import static org.junit.Assert.assertFalse;

public class UrlUtilsTest {
    @Test
    public void trimSlashes() {
        String urlStringWithSlashes = "/api/v1/endpoint/";

        String result = UrlUtils.trimSlashes(urlStringWithSlashes);

        assertFalse(result.matches("^/"));
        assertFalse(result.matches("/$"));
    }


}
