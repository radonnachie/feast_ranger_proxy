package za.co.discovery.health.bigdata.ranger.feast.dto;

import java.io.Serializable;

public class FeastResourceApplication implements Serializable {
    private String proto;
    private String last_updated_timestamp;

    public String getProto() {
		return proto;
	}
	public void setProto(String proto) {
		this.proto = proto;
	}

	public String getLast_updated_timestamp() {
		return last_updated_timestamp;
	}
	public void setLast_updated_timestamp(String last_updated_timestamp) {
		this.last_updated_timestamp = last_updated_timestamp;
	}

}
