package za.co.discovery.health.bigdata.ranger.feast.dto;

import java.io.Serializable;

public class FeastResource implements Serializable {
    private String name;
	private String type;
    private String project;

    public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}

	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}

	public String getProject() {
		return project;
	}
	public void setProject(String project) {
		this.project = project;
	}

}
