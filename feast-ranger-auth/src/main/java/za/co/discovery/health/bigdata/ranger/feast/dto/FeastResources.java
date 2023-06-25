package za.co.discovery.health.bigdata.ranger.feast.dto;

import java.io.Serializable;
import java.util.List;

public class FeastResources implements Serializable {
    private List<FeastResource> resources;

    public List<FeastResource> getResources() {
        return this.resources;
    }

    public void setResources(List<FeastResource> resources) {
        this.resources = resources;
    }
}
