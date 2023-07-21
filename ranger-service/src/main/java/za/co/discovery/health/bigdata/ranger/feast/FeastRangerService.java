package za.co.discovery.health.bigdata.ranger.feast;

import lombok.extern.log4j.Log4j2;
import org.apache.ranger.plugin.model.RangerService;
import org.apache.ranger.plugin.model.RangerServiceDef;
import org.apache.ranger.plugin.service.RangerBaseService;
import org.apache.ranger.plugin.service.ResourceLookupContext;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.*;
import java.util.stream.Collectors;

@Log4j2
public class FeastRangerService extends RangerBaseService {

    String feastUrl;

    @Override
    public void init(RangerServiceDef serviceDef, RangerService service){
        super.init(serviceDef, service);
        feastUrl = this.getConfigs().get("feast.url");
        log.info("feast.url is {}", feastUrl);
    }

    @Override
    public Map<String, Object> validateConfig() throws Exception {
        feastUrl = this.getConfigs().get("feast.url");
        log.info("feast.url is {}", feastUrl);
        if(feastUrl == null) {
            log.error("No url for feast has been specified");
            throw new Exception("No url for feast has been specified");
        }
        Map<String, Object> result = new HashMap<>();
        this.getConfigs().forEach((key, value) -> result.put(key, value));
        return result;
    }

    @Override
    public List<String> lookupResource(ResourceLookupContext resourceLookupContext) throws Exception {
        String resource = resourceLookupContext.getResourceName();
        RestTemplate restTemplate = new RestTemplate();

        switch(resource) {
            case "registry":
                return new ArrayList<String>(Arrays.asList(feastUrl));

            case "project_metadata":
            case "project":
                FeastProjects projects = restTemplate.getForObject(
                    UriComponentsBuilder.fromHttpUrl(feastUrl+"/projects")
                        .queryParam("name_like", resourceLookupContext.getUserInput())
                        .encode()
                        .toUriString(),
                    FeastProjects.class
                );
                return projects.getStrings();

            case "entity":
            case "data_source":
            case "feature_view":
            case "stream_feature_view":
            case "on_demand_feature_view":
            case "request_feature_view":
            case "feature_service":
            case "saved_dataset":
            case "validation_reference":
            default:
                FeastResources resources = restTemplate.getForObject(
                    UriComponentsBuilder.fromHttpUrl(feastUrl+"/resources")
                        .queryParam("resource", resource)
                        .queryParam("name_like", resourceLookupContext.getUserInput())
                        .encode()
                        .toUriString(),
                    FeastResources.class
                );
                return (List<String>) resources.getResources().stream().map(
                    r -> r.getProject() + "/" + r.getType() + "/" + r.getName()
                ).collect(Collectors.toList());
        }

    }
}
