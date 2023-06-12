package za.co.discovery.health.bigdata.ranger.feast.dto;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class FeastResourceProtos implements Serializable {
    private List<String> names;
    private List<String> protostrings;

    public List<String> getNames() {
        return this.names;
    }

    public void setNames(List<String> names) {
        this.names = names;
    }

    public List<String> getProtostrings() {
        return this.protostrings;
    }

    public void setProtostrings(List<String> protostrings) {
        this.protostrings = protostrings;
    }

    public Map<String, String> getNameProtostringMap() {
        return IntStream.range(0, this.names.size())
            .boxed()
            .collect(Collectors.toMap(this.names::get, this.protostrings::get));
    }
}
