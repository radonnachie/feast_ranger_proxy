package za.co.discovery.health.bigdata.ranger.feast;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.elasticsearch.*;

@SpringBootApplication(exclude ={org.springframework.boot.autoconfigure.elasticsearch.ElasticsearchRestClientAutoConfiguration.class,
        ElasticsearchDataAutoConfiguration.class, ElasticsearchRepositoriesAutoConfiguration.class})
public class FeastRangerApplication{

    public static void main(String[] args) {
        SpringApplication.run(FeastRangerApplication.class, args);
    }

}
