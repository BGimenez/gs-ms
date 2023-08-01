package br.com.gsistemas.gateway;

import br.com.gsistemas.gateway.util.CustomBanner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class GatewayApplication {

    public static void main(String[] args) {
//        SpringApplication.run(GatewayApplication.class, args);
        SpringApplication app = new SpringApplication(GatewayApplication.class);
        app.setBanner(new CustomBanner());
        app.run(args);
    }

}
