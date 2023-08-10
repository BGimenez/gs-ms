package br.com.gsistemas.auth;

import br.com.gsistemas.core.propertie.JwtConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableDiscoveryClient
@EnableConfigurationProperties(value = JwtConfiguration.class)
@EntityScan({"br.com.gsistemas.core.model"})
@EnableJpaRepositories({"br.com.gsistemas.core.repository"})
@ComponentScan("br.com.gsistemas")
public class AuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}

}
