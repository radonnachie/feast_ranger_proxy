/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package za.co.discovery.health.bigdata.ranger.feast;

import org.apache.ranger.plugin.audit.RangerDefaultAuditHandler;
import org.apache.ranger.plugin.policyengine.*;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.springframework.beans.factory.annotation.Value;

import java.util.*;

public class DefaultAuthorizer implements IAuthorizer {

    static {
        AccessTypeMap.put(AccessType.CREATE, "create");
        AccessTypeMap.put(AccessType.MODIFY, "modify");
        AccessTypeMap.put(AccessType.DELETE, "delete");
        AccessTypeMap.put(AccessType.READ, "read");
    }

    @Value("{ldap.service-principal}")
    private String ldapKerberosPrincipal;

    @Value("{feast.url}")
    private String feastRegistryUrl;

    public DefaultAuthorizer() {

    }
    private static volatile RangerBasePlugin plugin = null;

    public void init() {
        if (plugin == null) {
            synchronized (DefaultAuthorizer.class) {
                if (plugin == null) {
                    plugin = new RangerBasePlugin("feast", "cm_feast");

                    plugin.setResultProcessor(new RangerDefaultAuditHandler(plugin.getConfig()));
                    plugin.init();
                }
            }
        }
    }

    public void refresh(){
        plugin.refreshPoliciesAndTags();
    }

    @Override
    public boolean authorizeResourceAccess(
        AccessType accessType,
        String project,
        String resourceType,
        String resourceName,
        String user,
        Set<String> userGroups
    ) {
        return authorize(
            accessType,
            resourceType,
            String.format("%s/%s/%s", project, resourceType, resourceName),
            user,
            userGroups
        ) || authorizeProjectAccess(
            accessType == AccessType.READ ? AccessType.READ : AccessType.MODIFY,
            project,
            user,
            userGroups
        );
    }

    @Override
    public boolean authorizeProjectAccess(
        AccessType accessType,
        String project,
        String user,
        Set<String> userGroups
    ) {
        return authorize(
            accessType,
            "project",
            project,
            user,
            userGroups
        ) || authorizeRegistryAccess(
            accessType == AccessType.READ ? AccessType.READ : AccessType.MODIFY,
            user,
            userGroups
        );
    }

    @Override
    public boolean authorizeRegistryAccess(
        AccessType accessType,
        String user,
        Set<String> userGroups
    ) {
        return authorize(
            accessType,
            "registry",
            feastRegistryUrl,
            user,
            userGroups
        );
    }

    @Override
    public boolean authorize(AccessType accessType, String resourceType, String resourceUri, String user, Set<String> userGroups) {
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        resource.setValue(resourceType, resourceUri);
        RangerAccessRequest request = new RangerAccessRequestImpl(resource, AccessTypeMap.get(accessType), user, userGroups, null);
        RangerAccessResult result = plugin.isAccessAllowed(request);
        return result != null && result.getIsAllowed();
    }

    @Override
    public Map<String, Boolean> authorizeProjectResourceListAccess(
        String project,
        String resourceType,
        List<String> names,
        String user,
        Set<String> userGroups
    ) {
        final Map<String, Boolean> results = new HashMap<>();

        if (authorizeProjectAccess(
            AccessType.READ,
            project,
            user,
            userGroups
        )) {
            names.forEach(name -> {
                results.put(
                    name,
                    true
                );
            });
            return results;
        }

        final String resourceTypeAccess = AccessTypeMap.get(AccessType.READ);
        List<RangerAccessRequest> requests = new ArrayList<>();
        names.forEach(name -> {
            RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
            resource.setValue(resourceType, String.format("%s/%s/%s", project, resourceType, name));
            requests.add(
                new RangerAccessRequestImpl(
                    resource,
                    resourceTypeAccess,
                    user,
                    userGroups,
                    null
                )
            );
        });
        Collection<RangerAccessResult> accessResults = plugin.isAccessAllowed(requests);
        if(accessResults != null) {
            accessResults.forEach(accessResult ->
                results.put(
                    accessResult.getAccessRequest().getResource().getValue(resourceType).toString(),
                    accessResult.getIsAllowed()
                )
            );
        }
        return results;
    }

    @Override
    public Map<String, Boolean> authorizeRegistryProjectListAccess(
            List<String> projects,
            String user,
            Set<String> userGroups
    ) {
        final Map<String, Boolean> results = new HashMap<>();

        if (authorizeRegistryAccess(
                AccessType.READ,
                user,
                userGroups
        )) {
            projects.forEach(project -> {
                results.put(
                    project,
                    true
                );
            });
            return results;
        }

        final String resourceTypeAccess = AccessTypeMap.get(AccessType.READ);
        List<RangerAccessRequest> requests = new ArrayList<>();
        projects.forEach(project -> {
            RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
            resource.setValue("project", project);
            requests.add(
                new RangerAccessRequestImpl(
                    resource,
                    resourceTypeAccess,
                    user,
                    userGroups,
                    null
                )
            );
        });
        Collection<RangerAccessResult> accessResults = plugin.isAccessAllowed(requests);
        if(accessResults != null) {
            accessResults.forEach(accessResult ->
                results.put(
                    accessResult.getAccessRequest().getResource().getValue("project").toString(),
                    accessResult.getIsAllowed()
                )
            );
        }
        return results;
    }

}