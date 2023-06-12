package za.co.discovery.health.bigdata.ranger.feast.dto;

import java.io.Serializable;

public class FeastResourceDeletionCount implements Serializable {
    private int count;

    public int getCount() {
		return count;
	}
	public void setCount(int count) {
		this.count = count;
	}
}
