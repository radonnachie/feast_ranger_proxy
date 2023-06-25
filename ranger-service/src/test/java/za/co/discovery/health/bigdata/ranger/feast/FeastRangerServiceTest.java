package za.co.discovery.health.bigdata.ranger.feast;

import org.apache.ranger.plugin.service.ResourceLookupContext;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FeastRangerServiceTest {

    private final static String FEAST_URL = "http://localhost:80";
    private List<String> resourceTypes = new ArrayList<String>(Arrays.asList(
        "entity",
        "data_source",
        "feature_view",
        // "stream_feature_view",
        "on_demand_feature_view",
        // "request_feature_view",
        "feature_service"
        // "saved_dataset",
        // "validation_reference"
    ));

    @Test
    void lookupProjects() throws Exception {
        FeastRangerService service = new FeastRangerService();
        Map<String, String> configs = new HashMap<>();
        configs.put("feast.url", FEAST_URL);
        service.setConfigs(configs);
        service.validateConfig();
        ResourceLookupContext context = new ResourceLookupContext();
        context.setResourceName("project");
        context.setUserInput(null);
        List<String> projects = service.lookupResource(context);
        assertTrue(projects.size() > 0);
    }

    @Test
    void lookupProjectByName() throws Exception {
        FeastRangerService service = new FeastRangerService();
        Map<String, String> configs = new HashMap<>();
        configs.put("feast.url", FEAST_URL);
        service.setConfigs(configs);
        service.validateConfig();
        ResourceLookupContext context = new ResourceLookupContext();
        context.setResourceName("project");
        context.setUserInput(null);
        List<String> projects = service.lookupResource(context);

        service = new FeastRangerService();
        configs = new HashMap<>();
        configs.put("feast.url", FEAST_URL);
        service.setConfigs(configs);
        service.validateConfig();
        context = new ResourceLookupContext();
        context.setResourceName("project");
        context.setUserInput(projects.get(0));
        List<String> projects_by_name = service.lookupResource(context);
        assertTrue(projects_by_name.size() == 1);
    }

    @Test
    void lookupResource() throws Exception {
        FeastRangerService service = new FeastRangerService();
        Map<String, String> configs = new HashMap<>();
        configs.put("feast.url", FEAST_URL);
        service.setConfigs(configs);
        service.validateConfig();
        for (String resourceType : resourceTypes) {
            ResourceLookupContext context = new ResourceLookupContext();
            context.setResourceName(resourceType);
            context.setUserInput(null);
            List<String> resources = service.lookupResource(context);
            assertTrue(resources.size() > 0);
        }
    }

    @Test
    void lookupResourceByName() throws Exception {
        FeastRangerService service = new FeastRangerService();
        Map<String, String> configs = new HashMap<>();
        configs.put("feast.url", FEAST_URL);
        service.setConfigs(configs);
        service.validateConfig();
        for (String resourceType : resourceTypes) {
            ResourceLookupContext context = new ResourceLookupContext();
            context.setResourceName(resourceType);
            context.setUserInput(null);
            List<String> resources = service.lookupResource(context);

            context = new ResourceLookupContext();
            context.setResourceName(resourceType);
            context.setUserInput(resources.get(0));
            List<String> resources_by_name = service.lookupResource(context);
            assertTrue(resources_by_name.size() >= 1);
        }
    }

}