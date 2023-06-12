package za.co.discovery.health.bigdata.ranger.feast;

import org.apache.http.HttpException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URISyntaxException;
import java.util.UUID;

import static org.springframework.web.bind.annotation.RequestMethod.*;

@RestController
public class ProxyController {
    @Autowired
    ProxyService service;

    @RequestMapping(value="/health",  method = {GET})
    public ResponseEntity<?> sendGetHealthToSPQ(
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetHealth(
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/projects",  method = {GET})
    public ResponseEntity<?> sendGetProjectsToSPQ(
        // @RequestParam("name_like", required=false) String nameLike,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetProjects(
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/resources",  method = {GET})
    public ResponseEntity<?> sendGetResourcesToSPQ(
        // @RequestParam("name_like", required=false) String nameLike,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetResources(
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/teardown",  method = {DELETE})
    public ResponseEntity<?> sendDeleteTeardownToSPQ(
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processDeleteTeardown(
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/{project}",  method = {POST})
    public ResponseEntity<?> sendPostProjectResourceToSPQ(
        @PathVariable("project") String project,
        @RequestParam("resource") String resource,
        @RequestParam("name") String name,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processPostProjectResource(
            project,
            resource,
            name,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    
    }

    @RequestMapping(value="/{project}",  method = {DELETE})
    public ResponseEntity<?> sendDeleteProjectResourceToSPQ(
        @PathVariable("project") String project,
        @RequestParam("resource") String resource,
        @RequestParam("name") String name,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processDeleteProjectResource(
            project,
            resource,
            name,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    
    }

    @RequestMapping(value="/{project}",  method = {GET})
    public ResponseEntity<?> sendGetProjectResourceToSPQ(
        @PathVariable("project") String project,
        @RequestParam("resource") String resource,
        @RequestParam("name") String name,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetProjectResource(
            project,
            resource,
            name,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    
    }

    @RequestMapping(value="/{project}/list",  method = {GET})
    public ResponseEntity<?> sendGetProjectResourceListToSPQ(
        @PathVariable("project") String project,
        @RequestParam("resource") String resource,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetProjectResourceList(
            project,
            resource,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/{project}/last_updated",  method = {GET})
    public ResponseEntity<?> sendGetProjectLastUpdatedToSPQ(
        @PathVariable("project") String project,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetProjectLastUpdated(
            project,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/{project}/user_metadata",  method = {POST})
    public ResponseEntity<?> sendPostProjectUserMetadataToSPQ(
        @PathVariable("project") String project,
        @RequestParam("resource") String resource,
        @RequestParam("name") String name,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processPostProjectUserMetadata(
            project,
            resource,
            name,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/{project}/user_metadata",  method = {GET})
    public ResponseEntity<?> sendGetProjectUserMetadataToSPQ(
        @PathVariable("project") String project,
        @RequestParam("resource") String resource,
        @RequestParam("name") String name,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetProjectUserMetadata(
            project,
            resource,
            name,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

    @RequestMapping(value="/{project}/feast_metadata",  method = {GET})
    public ResponseEntity<?> sendGetProjectFeastMetadataToSPQ(
        @PathVariable("project") String project,
        @RequestBody(required = false) String body,
        HttpMethod method,
        HttpServletRequest request,
        HttpServletResponse response
    ) throws URISyntaxException, HttpException{
        return service.processGetProjectFeastMetadata(
            project,
            body,
            method,
            request,
            response,
            UUID.randomUUID().toString()
        );
    }

}