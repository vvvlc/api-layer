/*
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 */
package com.ca.mfaas.apicatalog.instance;

import com.ca.mfaas.apicatalog.model.APIContainer;
import com.ca.mfaas.apicatalog.services.cached.CachedProductFamilyService;
import com.ca.mfaas.apicatalog.services.cached.CachedServicesService;
import com.ca.mfaas.product.constants.CoreService;
import com.ca.mfaas.product.registry.CannotRegisterServiceException;
import com.netflix.appinfo.InstanceInfo;
import com.netflix.discovery.shared.Application;
import com.netflix.discovery.shared.Applications;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.retry.RetryException;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.stream.Collectors;

@Slf4j
@Service
public class InstanceInitializeService {

    private final CachedProductFamilyService cachedProductFamilyService;
    private final CachedServicesService cachedServicesService;
    private final InstanceRetrievalService instanceRetrievalService;

    private static final String API_ENABLED_METADATA_KEY = "mfaas.discovery.enableApiDoc";

    @Autowired
    public InstanceInitializeService(CachedProductFamilyService cachedProductFamilyService,
                                     CachedServicesService cachedServicesService,
                                     InstanceRetrievalService instanceRetrievalService) {
        this.cachedProductFamilyService = cachedProductFamilyService;
        this.cachedServicesService = cachedServicesService;
        this.instanceRetrievalService = instanceRetrievalService;
    }

    /**
     * Initialise the API Catalog with all current running instances
     * The API Catalog itself must be UP before checking all other instances
     * If the catalog is not up, or if the fetch fails, then wait for a defined period and retry up to a max of 5 times
     *
     * @throws CannotRegisterServiceException if the fetch fails or the catalog is not registered with the discovery
     */
    @Retryable(
        value = {RetryException.class},
        exclude = CannotRegisterServiceException.class,
        maxAttempts = 5,
        backoff = @Backoff(delayExpression = "#{${mfaas.service-registry.serviceFetchDelayInMillis}}"))
    public void retrieveAndRegisterAllInstancesWithCatalog() throws CannotRegisterServiceException {
        log.info("Initialising API Catalog with Discovery services.");
        try {
            String serviceId = CoreService.API_CATALOG.getServiceId();
            InstanceInfo apiCatalogInstance = instanceRetrievalService.getInstanceInfo(serviceId);
            if (apiCatalogInstance == null) {
                String msg = "API Catalog Instance not retrieved from Discovery service";
                log.warn(msg);
                throw new RetryException(msg);
            } else {
                log.info("API Catalog instance found, retrieving all services.");
                getAllInstances(apiCatalogInstance);
            }
        } catch (InstanceInitializationException e) {
            throw new RetryException(e.getMessage());
        } catch (Exception e) {
            String msg = "An unexpected exception occurred when trying to retrieve API Catalog instance from Discovery service";
            log.warn(msg, e);
            throw new CannotRegisterServiceException(msg, e);
        }
    }


    @Recover
    public void recover(RetryException e) {
        log.warn("Failed to initialise API Catalog with services running in the Gateway.");
    }

    /**
     * Only include services for caching if they have API doc enabled in their metadata
     *
     * @param discoveredServices all discovered services
     * @return only API Doc enabled services
     */
    private Applications filterByApiEnabled(Applications discoveredServices) {
        Applications filteredServices = new Applications();
        for (Application application : discoveredServices.getRegisteredApplications()) {
            if (!application.getInstances().isEmpty()) {
                processInstance(filteredServices, application);
            }
        }

        return filteredServices;
    }

    private void processInstance(Applications filteredServices, Application application) {
        InstanceInfo instanceInfo = application.getInstances().get(0);
        String value = instanceInfo.getMetadata().get(API_ENABLED_METADATA_KEY);
        boolean apiEnabled = true;
        if (value != null) {
            apiEnabled = Boolean.valueOf(value);
        }

        // only add api enabled services
        if (apiEnabled) {
            if (filteredServices == null) {
                filteredServices = new Applications();
            }
            filteredServices.addApplication(application);
        } else {
            log.debug("Service: " + application.getName() + " is not API enabled, it will be ignored by the API Catalog");
        }
    }

    /**
     * Query the discovery service forx all running instances
     */
    private void updateCacheWithAllInstances() {
        Applications allServices = instanceRetrievalService.getAllInstancesFromDiscovery(false);

        // Only include services which have API doc enabled
        allServices = filterByApiEnabled(allServices);

        // Return an empty string if no services are found after filtering
        if (allServices.getRegisteredApplications().isEmpty()) {
            log.info("No services found");
            return;
        }

        log.debug("Found: " + allServices.size() + " services on startup.");
        String s = allServices.getRegisteredApplications().stream()
            .map(Application::getName).collect(Collectors.joining(", "));
        log.debug("Discovered Services: " + s);

        // create containers for services
        for (Application application : allServices.getRegisteredApplications()) {
            createContainers(application);
        }

        // populate the cache
        Collection<APIContainer> containers = cachedProductFamilyService.getAllContainers();
        log.debug("Cache contains: " + containers.size() + " tiles.");
    }


    private void createContainers(Application application) {
        cachedServicesService.updateService(application.getName(), application);
        application.getInstances().forEach(instanceInfo -> {
            String productFamilyId = instanceInfo.getMetadata().get("mfaas.discovery.catalogUiTile.id");
            if (productFamilyId != null) {
                log.debug("Initialising product family (creating tile for) : " + productFamilyId);
                cachedProductFamilyService.createContainerFromInstance(productFamilyId, instanceInfo);
            }

        });
    }

    private void getAllInstances(InstanceInfo apiCatalogInstance) {
        String productFamilyId = apiCatalogInstance.getMetadata().get("mfaas.discovery.catalogUiTile.id");
        if (productFamilyId != null) {
            log.debug("Initialising product family (creating tile for) : " + productFamilyId);
            cachedProductFamilyService.createContainerFromInstance(productFamilyId, apiCatalogInstance);
        }

        updateCacheWithAllInstances();
        log.info("API Catalog initialised with running services..");
    }
}
