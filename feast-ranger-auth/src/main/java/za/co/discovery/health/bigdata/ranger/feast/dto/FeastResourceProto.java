package za.co.discovery.health.bigdata.ranger.feast.dto;

import java.io.Serializable;

public class FeastResourceProto implements Serializable {
    private String protostring;

    String getProtostring() {
        return this.protostring;
    }

    public void setProtostring(String protostring) {
        this.protostring = protostring;
    }
}
