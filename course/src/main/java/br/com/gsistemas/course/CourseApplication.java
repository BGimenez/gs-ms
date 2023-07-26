package br.com.gsistemas.course;

import br.com.gsistemas.core.model.Course;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableDiscoveryClient
@EntityScan({"br.com.gsistemas.core.model"})
@EnableJpaRepositories({"br.com.gsistemas.core.repository"})
public class CourseApplication {

	public static void main(String[] args) {
		SpringApplication.run(CourseApplication.class, args);
		System.out.println("Say: Hello");
		Course course = Course.builder()
				.id(1L)
				.title("Teste")
				.build();

		System.out.println("Course name: " + course.toString());
	}

}
