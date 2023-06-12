package za.co.discovery.health.bigdata.ranger.feast;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.http.entity.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.ranger.RangerClient;
import org.apache.ranger.RangerServiceException;
import org.apache.ranger.plugin.model.RangerPolicy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import za.co.discovery.health.bigdata.ranger.feast.dto.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;


@Service
public class ProxyService {
    HttpComponentsClientHttpRequestFactory httpRequestFactory;

    @Value("${feast.url}")
    String feastUrl;

    @Value("${ranger.url}")
    String rangerHostName = "http://172.16.0.86:6080";
    String rangerAuthType = "none";

    @Value("${ranger.admin}")
    String rangerUserName = "admin";
    @Value("${ranger.password}")
    String rangerPassword = "G0dz1ll421";

    @Value("${ranger.feast_service}")
    String rangerServiceName = "ross_feast";

    private final IAuthorizer authorizer;
    private final static Logger logger = LogManager.getLogger(ProxyService.class);

    ProxyService(IAuthorizer authorizer, HttpComponentsClientHttpRequestFactory httpRequestFactory){
        this.authorizer = authorizer;
        this.httpRequestFactory = httpRequestFactory;
    }

    public ResponseEntity<?> processGetHealth(
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        return buildProxiedResponse(body, method,  request,  response,  traceId, String.class);
    }

    public ResponseEntity<?> processGetProjects(
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        return buildProxiedResponse(body, method,  request,  response,  traceId, FeastProjects.class);
    }

    public ResponseEntity<?> processGetResources(
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        // TODO authorise
        String accessType = "read";
        return buildProxiedResponse(body, method,  request,  response,  traceId, FeastResources.class);
    }

    public ResponseEntity<?> processDeleteTeardown(
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        // TODO authorise
        return buildUnauthorisedResponse(request);
    }

    public ResponseEntity<?> processPostProjectResource(
        String project,
        String resource,
        String name,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        
        logger.info(requestUrl + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizePostRequest(
            project,
            resource,
            name,
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, String.class);
        }
        return buildUnauthorisedResponse(request);
    }

    public ResponseEntity<?> processDeleteProjectResource(
        String project,
        String resource,
        String name,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        
        logger.info(requestUrl + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeDeleteRequest(
            project,
            resource,
            name,
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceDeletionCount.class);
        }
        return buildUnauthorisedResponse(request);
    }

    public ResponseEntity<?> processGetProjectResource(
        String project,
        String resource,
        String name,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        
        logger.info(requestUrl + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeGetRequest(
            project,
            resource,
            name,
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceProto.class);
        }
        return buildUnauthorisedResponse(request);
    }

    public ResponseEntity<?> processGetProjectResourceList(
        String project,
        String resource,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ResponseEntity<FeastResourceProtos> resources = buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceProtos.class);
        if(resources == null || resources.getStatusCode() != HttpStatus.OK){
            return null;
        }
        List<String> names = Objects.requireNonNull(resources.getBody()).getNames();

        Map<String, Boolean> items = authorizer.authorizeListRequest(
            project,
            resource,
            names,
            user,
            groups
        );

        Map<String, String> nameProtostringMap resources.getBody().getNameProtostringMap();
        resources.getBody().setNames(
            nameProtostringMap.entrySet().stream()
                .filter(
                    kv ->
                        items.containsKey(kv.getKey()) && items.get(kv.getKey())
                )
                .collect(Collectors.toList())
        );
        resources.getBody().setProtostrings(
            resources.getBody().getNames().stream()
                .map(
                    name ->
                        nameProtostringMap.get(name)
                )
                .collect(Collectors.toList())
        );

        return resources;
    }

    public ResponseEntity<?> processGetProjectLastUpdated(
        String project,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        
        logger.info(requestUrl + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeGetProjectRequest(
            project,
            "last_updated",
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceLastUpdatedDatetime.class);
        }
        return buildUnauthorisedResponse(request);
    }

    public ResponseEntity<?> processPostProjectUserMetadata(
        String project,
        String resource,
        String name,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        
        logger.info(requestUrl + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizePostRequest(
            project,
            String(`${resource}_user_metadata`),
            name,
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, String.class);
        }
        return buildUnauthorisedResponse(request);
    }

    public ResponseEntity<?> processGetProjectUserMetadata(
        String project,
        String resource,
        String name,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        
        logger.info(requestUrl + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeGetRequest(
            project,
            String(`${resource}_user_metadata`),
            name,
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceProto.class);
        }
        return buildUnauthorisedResponse(request);
    }

    public ResponseEntity<?> processGetProjectFeastMetadata(
        String project,
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId
    ) throws URISyntaxException, HttpStatusCodeException {
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        
        logger.info(requestUrl + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeGetProjectRequest(
            project,
            "feast_metadata",
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceProtos.class);
        }
        return buildUnauthorisedResponse(request);
    }


    // @Retryable(
    //     exclude = {
    //         HttpStatusCodeException.class
    //     },
    //     include = Exception.class,
    //     backoff = @Backoff(
    //         delay = 5000,
    //         multiplier = 4.0
    //     ),
    //     maxAttempts = 4
    // )

    private HttpHeaders getHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.forEach((name, val) -> {
            if(!name.equals(HttpHeaders.CONTENT_LENGTH)){
                headers.put(name, val);
            }
        });
        return headers;
    }

    private void updateModelPolicy(String userName, String modelName){
        updatePolicy(userName, modelName, "model");
        authorizer.refresh();
    }

    private void updateExperimentPolicy(String userName, String experimentName){
        updatePolicy(userName, experimentName, "experiment");
        authorizer.refresh();
    }
    private void updatePolicy(String userName, String resourceName, String resourceType){
         /*
        Get a policy by name
         */
        Gson gsonBuilder = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ").setPrettyPrinting().create();
        RangerClient rangerClient = new RangerClient(rangerHostName, rangerAuthType, rangerUserName, rangerPassword, null);
        RangerPolicy fetchedPolicy = null;
        String policyName = userName + "_" +  resourceType;
        try {
            fetchedPolicy = rangerClient.getPolicy(rangerServiceName, policyName);
        } catch (RangerServiceException e) {
            logger.error(e);
        }
        try {
            if(fetchedPolicy == null){
                //create policy
                Map<String, RangerPolicy.RangerPolicyResource> resource = Collections.singletonMap(
                        resourceType, new RangerPolicy.RangerPolicyResource(Collections.singletonList(resourceName),false,false));
                RangerPolicy policy = new RangerPolicy();
                policy.setService(rangerServiceName);
                policy.setName(policyName);
                policy.setResources(resource);
                RangerPolicy.RangerPolicyItem policyItem = new RangerPolicy.RangerPolicyItem();
                policyItem.setUsers(Collections.singletonList(userName));
                List<RangerPolicy.RangerPolicyItemAccess> accesses = new ArrayList<>();
                accesses.add(new RangerPolicy.RangerPolicyItemAccess("delete-" + resourceType));
                accesses.add(new RangerPolicy.RangerPolicyItemAccess("edit-" + resourceType));
                if("model".equals(resourceType))
                    accesses.add(new RangerPolicy.RangerPolicyItemAccess("promote-model"));
                policyItem.setAccesses(accesses);
                policy.setPolicyItems(Collections.singletonList(policyItem));
                RangerPolicy createdPolicy = rangerClient.createPolicy(policy);
                logger.info("New Policy created successfully {}", gsonBuilder.toJson(createdPolicy));

            }else {
                logger.info("Policy: {} fetched {}", policyName, gsonBuilder.toJson(fetchedPolicy));

                //add new model to list
                fetchedPolicy.getResources().get(resourceType).getValues().add(resourceName);
                rangerClient.updatePolicy(rangerServiceName, policyName, fetchedPolicy);
                logger.info("Policy updated successfully {}", gsonBuilder.toJson(fetchedPolicy));
            }
        } catch (RangerServiceException e) {
            logger.error(e);
        }

    }
    private void removeModelPolicy(String userName, String modelName){
        removeResourceFromPolicy(userName, modelName, "model");
        authorizer.refresh();
    }

    private void removeExperimentPolicy(String userName, String experimentName){
        removeResourceFromPolicy(userName, experimentName, "experiment");
        authorizer.refresh();
    }
    private void removeResourceFromPolicy(String userName, String resourceName, String resourceType){
         /*
        Get a policy by name
         */
        Gson gsonBuilder = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ").setPrettyPrinting().create();
        RangerClient rangerClient = new RangerClient(rangerHostName, rangerAuthType, rangerUserName, rangerPassword, null);
        RangerPolicy fetchedPolicy;
        String policyName = userName + "_" +  resourceType;
        try {
            fetchedPolicy = rangerClient.getPolicy(rangerServiceName, policyName);
        } catch (RangerServiceException e) {
            logger.error(e);
            return;
        }
        try {

            logger.info("Policy: {} fetched {}", policyName, gsonBuilder.toJson(fetchedPolicy));

            //add new model to list
            fetchedPolicy.getResources().get(resourceType).getValues().remove(resourceName);
            rangerClient.updatePolicy(rangerServiceName, policyName, fetchedPolicy);
            logger.info("Policy updated successfully {}", gsonBuilder.toJson(fetchedPolicy));

        } catch (RangerServiceException e) {
            logger.error(e);
        }

    }

    private boolean matchUrl(String requestUrl, Commands cmd){
        return (requestUrl.contains(cmd.path) && requestUrl.contains(cmd.cmd));
    }

    private <T> ResponseEntity<T> buildProxiedResponse(
        String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response,
        String traceId,
        Class<T> responseType
    ) throws URISyntaxException {

        String requestUrl = request.getRequestURI();
        //log if required in this line
        URI uri = new URI(feastUrl);

        // replacing context path form urI to match actual gateway URI
        uri = UriComponentsBuilder.fromUri(uri)
                .path(requestUrl)
                .query(request.getQueryString())
                .build(true).toUri();

        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();

        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.set(headerName, request.getHeader(headerName));
        }

        HttpEntity<String> httpEntity = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate(this.httpRequestFactory);
        try {
            ResponseEntity<T> serverResponse = restTemplate.exchange(uri, method, httpEntity, responseType);
            logger.info(serverResponse);
            return serverResponse;
        } catch (HttpStatusCodeException e) {
            logger.error(e.getMessage());
            return (ResponseEntity<T>) ResponseEntity
                .status(e.getRawStatusCode())
                .headers(e.getResponseHeaders())
                .body(e.getResponseBodyAsString());
        }
    }

    private ResponseEntity<String> buildUnauthorisedResponse(HttpServletRequest request){

        HttpHeaders headers = new HttpHeaders();

        logger.info("Unauthorised " + request);
        List<String> contentTypes = new ArrayList<>();
        contentTypes.add(ContentType.APPLICATION_JSON.toString());
        headers.put(HttpHeaders.CONTENT_TYPE, contentTypes);
        return ResponseEntity.status(403)
                .headers(headers)
                .body("{\"error_code\": \"UNAUTHORISED\", \"message\": \"You do not have permissions to access this resource\"}");
    }

    private String getValFromQueryString(String queryString, String name){
        if(queryString == null) return null;
        String[] nameValPairs = queryString.split(",");
        for(String item : nameValPairs){
            String[] keyVal = item.split("=");
            if(name.equals(keyVal[0]))
                return keyVal[1];
        }
        return null;
    }

    @Recover
    public ResponseEntity<String> recoverFromRestClientErrors(Exception e, String body,
                                                              HttpMethod method, HttpServletRequest request, HttpServletResponse response, String traceId) {
        logger.error("retry method for the following url " + request.getRequestURI() + " has failed" + e.getMessage());
        logger.error(e.getStackTrace());
        throw new RuntimeException("There was an error trying to process your request. Please try again later");
    }
}