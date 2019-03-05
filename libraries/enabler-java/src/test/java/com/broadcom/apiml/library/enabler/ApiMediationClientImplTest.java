/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.broadcom.apiml.library.enabler;


import com.broadcom.apiml.library.enabler.config.*;
import com.broadcom.apiml.library.enabler.impl.ApiMediationClientImpl;
import com.broadcom.apiml.library.enabler.util.ApiMediationServiceConfigReader;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.List;


@Ignore
public class ApiMediationClientImplTest {
    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void startEurekaClient() {
        ShortApiInfo shortApiInfo = new ShortApiInfo("Hello World Spring", "REST API for a Spring Application", "1.0.0");
        CatalogUiTile catalogUiTile = new CatalogUiTile("cademoapps", "Sample API Mediation Layer Applications", "Applications which demonstrate how to make a service integrated to the API Mediation Layer ecosystem", "1.0.0");
        Eureka eureka = new Eureka("10020", "localhost", "127.0.0.1");
        Ssl ssl = new Ssl(false, "TLSv1.2", "localhost", "password",
            "../keystore/localhost/localhost.keystore.p12", "password", "PKCS12",
            "../keystore/localhost/localhost.truststore.p12", "password", "PKCS12");
        List<Route> routes = new ArrayList<>();
        Route apiRoute = new Route("api/v1", "/hellospring/api/v1");
        Route apiDocRoute = new Route("api/v1/api-doc", "/hellospring/api-doc");
        routes.add(apiRoute);
        routes.add(apiDocRoute);
        ApiMediationClient client = new ApiMediationClientImpl();
        ApiMediationServiceConfig config = ApiMediationServiceConfig.builder()
            .shortApiInfo(shortApiInfo)
            .eureka(eureka)
            .catalogUiTile(catalogUiTile)
            .routes(routes)
            .description("Example for exposing a Spring REST API")
            .title("Hello Spring REST API")
            .serviceId("service")
            .baseUrl("http://host:1000/service")
            .healthCheckRelativeUrl("")
            .homePageRelativeUrl("")
            .statusPageRelativeUrl("")
            .discoveryServiceUrl("https://localhost:10011/eureka")
            .ssl(ssl)
            .build();

        client.register(config);
        client.unregister();
    }

    @Test
    public void badBaseUrlFormat() {
        String file = "/bad-baseurl-service-configuration.yml";
        ApiMediationClient client = new ApiMediationClientImpl();
        ApiMediationServiceConfig config = new ApiMediationServiceConfigReader(file).readConfiguration();
        exceptionRule.expect(RuntimeException.class);
        exceptionRule.expectMessage("baseUrl: [localhost:10020/hellospring] is not valid URL");

        client.register(config);
        client.unregister();
    }

    @Test
    public void httpsBaseUrlFormat() {
        String file = "/https-service-configuration.yml";
        ApiMediationClient client = new ApiMediationClientImpl();
        ApiMediationServiceConfig config = new ApiMediationServiceConfigReader(file).readConfiguration();

        client.register(config);
        client.unregister();
    }

    @Test
    public void badProtocolForBaseUrl() {
        String file = "/bad-protocol-baseurl-service-configuration.yml";
        ApiMediationClient client = new ApiMediationClientImpl();
        ApiMediationServiceConfig config = new ApiMediationServiceConfigReader(file).readConfiguration();
        exceptionRule.expect(RuntimeException.class);
        exceptionRule.expectMessage("Invalid protocol for baseUrl property");

        client.register(config);
        client.unregister();
    }

}
