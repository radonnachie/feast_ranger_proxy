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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

interface IAuthorizer {
    public static enum AccessType {
        CREATE,
        MODIFY,
        DELETE,
        READ
    }

    public static Map<AccessType, String> AccessTypeMap = new HashMap<>();

    void init();

    boolean authorize(
            AccessType accessType,
            String resourceType,
            String resourceUri,
            String user,
            Set<String> userGroups
    );

    boolean authorizeRegistryAccess(
            AccessType accessType,
            String user,
            Set<String> userGroups
    );

    boolean authorizeProjectAccess(
            AccessType accessType,
            String project,
            String user,
            Set<String> userGroups
    );

    boolean authorizeResourceAccess(
            AccessType accessType,
            String project,
            String resourceType,
            String resourceName,
            String user,
            Set<String> userGroups
    );

    Map<String, Boolean> authorizeProjectResourceListAccess(
            String project,
            String resourceType,
            List<String> names,
            String user,
            Set<String> userGroups
    );

    Map<String, Boolean> authorizeRegistryProjectListAccess(
            List<String> projects,
            String user,
            Set<String> userGroups
    );

    void refresh();
}
