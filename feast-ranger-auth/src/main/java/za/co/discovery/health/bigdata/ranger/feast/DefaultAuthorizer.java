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

import java.util.*;

public class DefaultAuthorizer implements IAuthorizer {
    public static Map<String, String> PostRequestAccessTypeMap;
    public static Map<String, String> DeleteRequestAccessTypeMap;
    public static Map<String, String> GetRequestAccessTypeMap;
    public static Map<String, String> ListRequestAccessTypeMap;
    static {
        PostRequestAccessTypeMap = new HashMap<>();
        PostRequestAccessTypeMap.put("entity", "modify_entity");
        PostRequestAccessTypeMap.put("data_source", "modify_data_source");
        PostRequestAccessTypeMap.put("feature_service", "modify_feature_service");
        PostRequestAccessTypeMap.put("feature_view", "modify_feature_view");
        PostRequestAccessTypeMap.put("stream_feature_view", "modify_stream_feature_view");
        PostRequestAccessTypeMap.put("on_demand_feature_view", "modify_on_demand_feature_view");
        PostRequestAccessTypeMap.put("request_feature_view", "modify_request_feature_view");
        PostRequestAccessTypeMap.put("validation_reference", "modify_validation_reference");
        PostRequestAccessTypeMap.put("saved_dataset", "modify_saved_dataset");
        PostRequestAccessTypeMap.put("managed_infra", "modify_managed_infra");
        PostRequestAccessTypeMap.put("feature_view_user_metadata", "modify_feature_view_user_metadata");
        PostRequestAccessTypeMap.put("stream_feature_view_user_metadata", "modify_stream_feature_view_user_metadata");
        PostRequestAccessTypeMap.put("on_demand_feature_view_user_metadata", "modify_on_demand_feature_view_user_metadata");
        PostRequestAccessTypeMap.put("request_feature_view_user_metadata", "modify_request_feature_view_user_metadata");

        DeleteRequestAccessTypeMap = new HashMap<>();
        DeleteRequestAccessTypeMap.put("entity", "delete_entity");
        DeleteRequestAccessTypeMap.put("data_source", "delete_data_source");
        DeleteRequestAccessTypeMap.put("feature_service", "delete_feature_service");
        DeleteRequestAccessTypeMap.put("feature_view", "delete_feature_view");
        DeleteRequestAccessTypeMap.put("validation_reference", "delete_validation_reference");
        DeleteRequestAccessTypeMap.put("teardown", "delete");

        GetRequestAccessTypeMap = new HashMap<>();
        GetRequestAccessTypeMap.put("entity", "get_entity");
        GetRequestAccessTypeMap.put("data_source", "get_data_source");
        GetRequestAccessTypeMap.put("feature_service", "get_feature_service");
        GetRequestAccessTypeMap.put("feature_view", "get_feature_view");
        GetRequestAccessTypeMap.put("stream_feature_view", "get_stream_feature_view");
        GetRequestAccessTypeMap.put("on_demand_feature_view", "get_on_demand_feature_view");
        GetRequestAccessTypeMap.put("request_feature_view", "get_request_feature_view");
        GetRequestAccessTypeMap.put("validation_reference", "get_validation_reference");
        GetRequestAccessTypeMap.put("saved_dataset", "get_saved_dataset");
        GetRequestAccessTypeMap.put("managed_infra", "get_managed_infra");
        GetRequestAccessTypeMap.put("feature_view_user_metadata", "get_feature_view_user_metadata");
        GetRequestAccessTypeMap.put("stream_feature_view_user_metadata", "get_stream_feature_view_user_metadata");
        GetRequestAccessTypeMap.put("on_demand_feature_view_user_metadata", "get_on_demand_feature_view_user_metadata");
        GetRequestAccessTypeMap.put("request_feature_view_user_metadata", "get_request_feature_view_user_metadata");
        GetRequestAccessTypeMap.put("project_metadata", "get_project_metadata");

        ListRequestAccessTypeMap = new HashMap<>();
        ListRequestAccessTypeMap.put("entity", "list_entity");
        ListRequestAccessTypeMap.put("data_source", "list_data_source");
        ListRequestAccessTypeMap.put("feature_service", "list_feature_service");
        ListRequestAccessTypeMap.put("feature_view", "list_feature_view");
        ListRequestAccessTypeMap.put("stream_feature_view", "list_stream_feature_view");
        ListRequestAccessTypeMap.put("on_demand_feature_view", "list_on_demand_feature_view");
        ListRequestAccessTypeMap.put("request_feature_view", "list_request_feature_view");
        ListRequestAccessTypeMap.put("validation_reference", "list_validation_reference");
        ListRequestAccessTypeMap.put("saved_dataset", "list_saved_dataset");
    }

    public DefaultAuthorizer() {

    }
    private static volatile RangerBasePlugin plugin = null;

    public void init() {
        if (plugin == null) {
            synchronized (DefaultAuthorizer.class) {
                if (plugin == null) {
                    plugin = new RangerBasePlugin("feast", "feast");

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
    public boolean authorizePostRequest(
        String project,
        String resourceType,
        String name,
        String user,
        Set<String> userGroups
    ) {
        return authorize(
            PostRequestAccessTypeMap.get(resourceType),
            resourceType,
            String.format("%s/%s/%s", project, resourceType, name), // resource uri
            user,
            userGroups
        );
    }

    @Override
    public boolean authorizeDeleteRequest(
        String project,
        String resourceType,
        String name,
        String user,
        Set<String> userGroups
    ) {
        return authorize(
            DeleteRequestAccessTypeMap.get(resourceType),
            resourceType,
            String.format("%s/%s/%s", project, resourceType, name), // resource uri
            user,
            userGroups
        );
    }

    @Override
    public boolean authorizeGetRequest(
        String project,
        String resourceType,
        String name,
        String user,
        Set<String> userGroups
    ) {
        return authorize(
            PostRequestAccessTypeMap.get(resourceType),
            resourceType,
            String.format("%s/%s/%s", project, resourceType, name), // resource uri
            user,
            userGroups
        );
    }

    @Override
    public boolean authorizeGetProjectRequest(
        String project,
        String resourceType,
        String user,
        Set<String> userGroups
    ) {
        return authorize(
            GetRequestAccessTypeMap.get("project_metadata"),
            resourceType,
            String.format("%s/%s", project, resourceType), // resource uri
            user,
            userGroups
        );
    }

    public boolean authorize(String accessType, String resourceType, String artifact, String user, Set<String> userGroups) {
        RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
        resource.setValue(resourceType, artifact);
        RangerAccessRequest request = new RangerAccessRequestImpl(resource, accessType, user, userGroups, null);
        RangerAccessResult result = plugin.isAccessAllowed(request);
        return result != null && result.getIsAllowed();
    }

    @Override
    public Map<String, Boolean> authorizeListRequest(
        String project,
        String resourceType,
        List<String> names,
        String user,
        Set<String> userGroups
    ) {
        final Map<String, Boolean> results = new HashMap<>();
        List<RangerAccessRequest> requests = new ArrayList<>();
        names.forEach(name -> {
            RangerAccessResourceImpl resource = new RangerAccessResourceImpl();
            resource.setValue(resourceType, name);
            requests.add(
                new RangerAccessRequestImpl(
                    resource,
                    ListRequestAccessTypeMap.get("resourceType"),
                    user,
                    userGroups,
                    null
                )
            );
        });
        Collection<RangerAccessResult> accessResults = plugin.isAccessAllowed(requests);
        accessResults.forEach(accessResult ->
                results.put(
                    accessResult.getAccessRequest().getResource().getValue(resourceType).toString(),
                    accessResult.getIsAllowed()
                )
        );
        return results;
    }

}