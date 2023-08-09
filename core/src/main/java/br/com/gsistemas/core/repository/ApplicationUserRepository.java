package br.com.gsistemas.core.repository;


import br.com.gsistemas.core.model.ApplicationUser;
import br.com.gsistemas.core.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {
    ApplicationUser findByUsername(String username);
}
