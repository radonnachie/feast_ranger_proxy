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
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
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
import java.util.stream.IntStream;


public class ProxyService {
    HttpComponentsClientHttpRequestFactory httpRequestFactory;

    private final String feastUrl;
    private final String rangerServiceName;

    private final IAuthorizer authorizer;
    private final RangerClient rangerClient;
    private final static Logger logger = LogManager.getLogger(ProxyService.class);

    ProxyService(
        IAuthorizer authorizer,
        HttpComponentsClientHttpRequestFactory httpRequestFactory,

        String feastUrl,
        String rangerHostName,
        String rangerAuthType,
        String rangerKeytab,
        String rangerUserName,
        String rangerPassword,
        String rangerServiceName

    ){
        this.feastUrl = feastUrl;
        this.rangerServiceName = rangerServiceName;
        this.authorizer = authorizer;
        this.httpRequestFactory = httpRequestFactory;

        if(rangerAuthType.equals("kerberos")){
            this.rangerClient = new RangerClient(
                rangerHostName,
                rangerAuthType,
                rangerUserName,
                rangerKeytab,
                null
            );
        }else{
            this.rangerClient = new RangerClient(
                rangerHostName,
                rangerAuthType,
                rangerUserName,
                rangerPassword,
                null
            );
        }
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
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        logger.info(request.getRequestURI() + ", " + request.getQueryString());
        logger.info(body);

        ResponseEntity<FeastProjects> projects_response = buildProxiedResponse(body, method,  request,  response,  traceId, FeastProjects.class);
        if(projects_response == null || projects_response.getStatusCode() != HttpStatus.OK){
            return null;
        }
        FeastProjects projects = Objects.requireNonNull(projects_response.getBody());
        List<String> projectNames = projects.getStrings();

        Map<String, Boolean> items = authorizer.authorizeRegistryProjectListAccess(
            projectNames,
            user,
            groups
        );

        projects.setStrings(
            projectNames.stream()
            .filter(
                projectName -> items.containsKey(projectName) && items.get(projectName)
            )
            .collect(Collectors.toList())
        );

        HttpHeaders headers = new HttpHeaders();
        List<String> contentTypes = new ArrayList<>();
        contentTypes.add(ContentType.APPLICATION_JSON.toString());
        headers.put(HttpHeaders.CONTENT_TYPE, contentTypes);
        return (ResponseEntity<FeastProjects>) ResponseEntity
            .status(projects_response.getStatusCode())
            .headers(headers)
            .body(projects);
    }

    public ResponseEntity<?> processDeleteTeardown(
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

        if (authorizer.authorizeRegistryAccess(
            IAuthorizer.AccessType.DELETE, // delete project within the registry
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, String.class);
        }
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
            user = user.split("@")[0].toLowerCase();
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(
                item -> item.getAuthority().toLowerCase()
        ).collect(Collectors.toSet());

        // determine 'put' or 'patch' (i.e. whether or not the resource already exists)
        URI uri = UriComponentsBuilder.fromHttpUrl(feastUrl)
            .path(project)
            .queryParam("resource", resource)
            .queryParam("name", name)
            .build(true).toUri();
        HttpEntity<String> httpEntity = new HttpEntity<>(body, new HttpHeaders());
        RestTemplate restTemplate = new RestTemplate(this.httpRequestFactory);
        ResponseEntity<FeastResourceProto> serverResponse = restTemplate.exchange(uri, method, httpEntity, FeastResourceProto.class);

        boolean authorized = false;
        if (serverResponse.getStatusCode() == HttpStatus.OK) {
            authorized = authorizer.authorizeResourceAccess( // modify existing resource
                IAuthorizer.AccessType.MODIFY,
                project,
                resource,
                name,
                user,
                groups
            );
        } else if (serverResponse.getStatusCode() == HttpStatus.NOT_FOUND) {
            authorized = authorizer.authorizeProjectAccess(
                IAuthorizer.AccessType.CREATE, // create resource within the project
                project,
                user,
                groups
            );
            if (authorized) {
                try {
                    createResourcePolicy(
                        user,
                        resource,
                        String.format("%s/%s/%s", project, resource, name),
                        new HashSet<>(Arrays.asList(
                            IAuthorizer.AccessType.CREATE,
                            IAuthorizer.AccessType.MODIFY,
                            IAuthorizer.AccessType.DELETE,
                            IAuthorizer.AccessType.READ
                        ))
                    );
                } catch (RangerServiceException e) {
                    logger.error(e);
                    return buildErrorResponse(
                        request,
                        e
                    );
                }
            }
        } else {
            return buildErrorResponse(
                request,
                new RuntimeException(
                    "Feast response code was neither 200 nor 404: " + serverResponse.getStatusCode().toString()
                )
            );
        }

        if (authorized) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, String.class);
            // TODO handle non-200 authorized response...
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
        
        logger.info(request.getRequestURI() + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeResourceAccess(
                IAuthorizer.AccessType.DELETE, // delete existing resource
                project,
                resource,
                name,
                user,
                groups
        )) {
            try {
                removeResourcePolicy(
                        String.format("%s/%s/%s", project, resource, name)
                );
            } catch (RangerServiceException e) {
                logger.error(e);
            }
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
        logger.info(authentication);
        String user = authentication == null ? null: authentication.getName();
        logger.info(user);
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        logger.info(groups);

        if (authorizer.authorizeResourceAccess(
            IAuthorizer.AccessType.READ,
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
        ThreadContext.put("traceId", traceId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String user = authentication == null ? null: authentication.getName();
        if(user != null){
            user = user.split("@")[0];
        }
        Collection<GrantedAuthority> grantedAuthorities = authentication == null ? null: (Collection<GrantedAuthority>) authentication.getAuthorities();
        assert grantedAuthorities != null;
        Set<String> groups =  grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        logger.info(request.getRequestURI() + ", " + request.getQueryString());
        logger.info(body);

        ResponseEntity<FeastResourceProtos> resources_response = buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceProtos.class);
        if(resources_response == null || resources_response.getStatusCode() != HttpStatus.OK){
            return null;
        }
        FeastResourceProtos resources = Objects.requireNonNull(resources_response.getBody());
        List<String> names = resources.getNames();

        Map<String, Boolean> items = authorizer.authorizeProjectResourceListAccess(
            project,
            resource,
            names,
            user,
            groups
        );

        Map<String, String> nameProtostringMap = IntStream
            .range(0, resources.getNames().size())
            .boxed()
            .collect(Collectors.toMap(
                resources.getNames()::get,
                resources.getProtostrings()::get
            )
        );
        resources.setNames(
            nameProtostringMap.entrySet().stream()
                .filter(
                    kv ->
                        items.containsKey(kv.getKey()) && items.get(kv.getKey())
                )
                .map(kv -> kv.getKey())
                .collect(Collectors.toList())
        );
        resources.setProtostrings(
            resources.getNames().stream()
                .map(
                        nameProtostringMap::get
                )
                .collect(Collectors.toList())
        );

        HttpHeaders headers = new HttpHeaders();
        List<String> contentTypes = new ArrayList<>();
        contentTypes.add(ContentType.APPLICATION_JSON.toString());
        headers.put(HttpHeaders.CONTENT_TYPE, contentTypes);
        return (ResponseEntity<FeastResourceProtos>) ResponseEntity
                .status(resources_response.getStatusCode())
                .headers(headers)
                .body(resources);
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

        // TODO breakup into create/modify on String.format("%s_user_metadata", resource),

        logger.info(request.getRequestURI() + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeResourceAccess(
            IAuthorizer.AccessType.MODIFY,
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

        logger.info(request.getRequestURI() + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeResourceAccess(
            IAuthorizer.AccessType.READ,
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

    public ResponseEntity<?> processGetProjectDetail(
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

        logger.info(request.getRequestURI() + ", " + request.getQueryString());
        logger.info(body);
        if (authorizer.authorizeProjectAccess(
            IAuthorizer.AccessType.READ,
            project,
            user,
            groups
        )) {
            return buildProxiedResponse(body, method,  request,  response,  traceId, FeastResourceProtos.class);
        }
        return buildUnauthorisedResponse(request);
    }

    private void createResourcePolicy(
        String userName,
        String resourceType,
        String resourceUri,
        Set<IAuthorizer.AccessType> accessTypes
    ) throws RangerServiceException {
        String policyName = resourceUri;
        // create policy
        // TODO set group of new policy
        Map<String, RangerPolicy.RangerPolicyResource> resource = Collections.singletonMap(
            resourceType,
            new RangerPolicy.RangerPolicyResource(Collections.singletonList(resourceUri),false,false)
        );
        RangerPolicy policy = new RangerPolicy();
        policy.setService(rangerServiceName);
        policy.setName(policyName);
        policy.setResources(resource);
        RangerPolicy.RangerPolicyItem policyItem = new RangerPolicy.RangerPolicyItem();
        policyItem.setUsers(Collections.singletonList(userName));
        List<RangerPolicy.RangerPolicyItemAccess> accesses = new ArrayList<>();
        for (IAuthorizer.AccessType accessType: accessTypes) {
            accesses.add(new RangerPolicy.RangerPolicyItemAccess(authorizer.AccessTypeMap.get(accessType)));
        }
        policyItem.setAccesses(accesses);
        policy.setPolicyItems(Collections.singletonList(policyItem));

        RangerPolicy createdPolicy = rangerClient.createPolicy(policy);
        Gson gsonBuilder = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ").setPrettyPrinting().create();
        logger.info("New Policy created successfully {}", gsonBuilder.toJson(createdPolicy));
    }

    private void removeResourcePolicy(String resourceUri) throws RangerServiceException {
        String policyName = resourceUri;
        rangerClient.deletePolicy(rangerServiceName, policyName);
        authorizer.refresh();
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
        logger.info(uri);
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
            .body("{\"detail\": \"You do not have permissions to access this resource\"}");
    }

    private ResponseEntity<String> buildErrorResponse(
        HttpServletRequest request,
        Exception error
    ){
        HttpHeaders headers = new HttpHeaders();

        logger.info("Failed " + request);
        List<String> contentTypes = new ArrayList<>();
        contentTypes.add(ContentType.APPLICATION_JSON.toString());
        headers.put(HttpHeaders.CONTENT_TYPE, contentTypes);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .headers(headers)
            .body("{\"detail\": \""+error+"\"}");
    }

}