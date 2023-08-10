package br.com.gsistemas.security.config;

import br.com.gsistemas.core.propertie.JwtConfiguration;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

/**
 * Forma depreciada
 *
 * @EnableWebSecurity
 * public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
 *    // métodos de configuração
 * }
 *
 * A anotacao @EnableMethodSecurity é usada para habilitar o uso das anotacoes com as regras de seguranca, como a
 * @PreAuthorize. Antes era utilizado @EnableGlobalMethodSecurity
 */
@RequiredArgsConstructor
public class SecurityTokenConfig {

    protected final JwtConfiguration jwtConfiguration;

    /**
     * Forma Depreciada
     * @Bean
     * public SecurityFilterChain configure(HttpSecurity http) throws Exception {
     *     http.authorizeHttpRequests( (authorize) -> authorize
     *            .requestMatchers("/").permitAll()
     *            .requestMatchers("/user/cadastro").hasAuthority(ADMIN)
     *            .anyRequest().authenticated()
     *      )
     *     .formLogin()
     *        .loginPage("/login")
     *        .defaultSuccessUrl("/", true)
     *        .failureUrl("/login-error")
     *        .permitAll()
     *     .and()
     *        .logout()
     *        .logoutSuccessUrl("/")
     *        .deleteCookies("JSESSIONID")
     *     .and()
     *        .exceptionHandling()
     *        .accessDeniedPage("/negado");
     *
     *     return http.build();
     * }
     *
     *
     * @param http
     * @return
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                //Disable CSRF
                .csrf((csrfConf) -> csrfConf.disable())
//                Configure CORS
                .cors(corsConf -> corsConf.configurationSource(req -> new CorsConfiguration().applyPermitDefaultValues()))
                //Garante que estamos usando sessao stateless; a sessao nao deve ser usada para armazenar o estado do usuario
                .sessionManagement(sessionConf -> sessionConf.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exConf -> exConf.authenticationEntryPoint((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED)))
                .authorizeHttpRequests((authz) -> authz
                        //Nao autentica essa URL especifica
                        .requestMatchers(jwtConfiguration.getLoginUrl()).permitAll()
                        .requestMatchers("/course/admin/**").hasRole("ADMIN")
                        //Todas as outras requisicoes precisam ser autenticadas
                        .anyRequest().authenticated()
                )
                .build();
    }

}
