package br.com.gsistemas.auth.security.user;

import br.com.gsistemas.core.model.ApplicationUser;
import br.com.gsistemas.core.repository.ApplicationUserRepository;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;

import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;

@RequiredArgsConstructor
@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    private final ApplicationUserRepository applicationUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Searching in the DB the user by username '{}'", username);

        ApplicationUser usuario = applicationUserRepository.findByUsername(username);

        log.info("ApplicationUser found '{}'", usuario);

        if(usuario == null) {
            throw new UsernameNotFoundException(String.format("Application user %s not found", username));
        }

        return new CustomUserDetails(usuario);
    }

    private static final class CustomUserDetails extends ApplicationUser implements UserDetails {

        CustomUserDetails(@NotNull ApplicationUser applicationUser) {
            super(applicationUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return commaSeparatedStringToAuthorityList("ROLE_"+this.getRole());
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
