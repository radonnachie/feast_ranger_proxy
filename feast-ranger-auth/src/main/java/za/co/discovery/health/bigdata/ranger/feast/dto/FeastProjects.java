package za.co.discovery.health.bigdata.ranger.feast.dto;

import java.io.Serializable;
import java.util.List;

public class FeastProjects implements Serializable {
    private List<String> strings;

    List<String> getStrings() {
        return this.strings;
    }

    public void setStrings(List<String> strings) {
        this.strings = strings;
    }
}
