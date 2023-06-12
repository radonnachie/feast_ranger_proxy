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

import java.util.List;
import java.util.Map;
import java.util.Set;

interface IAuthorizer {
    void init();

    boolean authorizePostRequest(
        String project,
        String resource,
        String name,
        String user,
        Set<String> userGroups
    );

    boolean authorizeDeleteRequest(
        String project,
        String resource,
        String name,
        String user,
        Set<String> userGroups
    );

    boolean authorizeGetRequest(
        String project,
        String resource,
        String name,
        String user,
        Set<String> userGroups
    );

    Map<String, Boolean> authorizeListRequest(
        String project,
        String resource,
        List<String> names,
        String user,
        Set<String> userGroups
    );
    
    boolean authorizeGetProjectRequest(
        String project,
        String resource,
        String user,
        Set<String> userGroups
    );

    Map<String, Boolean> authorizeResourceList(List<String> models, String user, Set<String> userGroups);

    void refresh();
}
