package br.com.gsistemas.auth.security.config;

import br.com.gsistemas.auth.security.filter.JwtUsernameAndPasswordAuthenticationFilter;
import br.com.gsistemas.core.propertie.JwtConfiguration;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
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
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityCredentialsConfig {

    private final UserDetailsService userDetailsService;
    private final JwtConfiguration jwtConfiguration;

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
//        http
//                .csrf().disable()
//                .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
//                .and()
//                .sessionManagement().sessionCreationPolicy(STATELESS)
//                .and()
//                .exceptionHandling().authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
//                .and()
//                .addFilter(new UsernamePasswordAuthenticationFilter())
//                .authorizeRequests()
//                .antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
//                .antMatchers("/course/admin/**").hasRole("ADMIN")
//                .anyRequest().authenticated();
        return http
                //Disable CSRF
                .csrf((csrfConf) -> csrfConf.disable())
//                Configure CORS
                .cors(corsConf -> corsConf.configurationSource(req -> new CorsConfiguration().applyPermitDefaultValues()))
                //Garante que estamos usando sessao stateless; a sessao nao deve ser usada para armazenar o estado do usuario
                .sessionManagement(sessionConf -> sessionConf.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exConf -> exConf.authenticationEntryPoint((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED)))

                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(http.getSharedObject(AuthenticationConfiguration.class)), jwtConfiguration))
                .authorizeHttpRequests((authz) -> authz
                        //Nao autentica essa URL especifica
                        .requestMatchers(jwtConfiguration.getLoginUrl()).permitAll()
                        .requestMatchers("/course/admin/**").hasRole("ADMIN")
                        //Todas as outras requisicoes precisam ser autenticadas
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authProvider())
                .build();
    }

    /**
     * Forma Depreciada
     * protected void configure(AuthenticationManagerBuilder auth) throws Exception {
     * 		auth.userDetailsService(userDetailsService)
     *         .passwordEncoder(new BCryptPasswordEncoder());
     * }
     *
     * Apenas com o método passwordEncoder, nao é mais necessário incluir esse.
     * https://cursos.alura.com.br/forum/topico-dificuldade-em-substituir-o-websecurityconfigureradapter-275194
     *
     * @return
     */
//    @Bean
//    public HttpSecurity authenticationManager(HttpSecurity http,
//                                                       PasswordEncoder passwordEncoder,
//                                                       UserDetailsService userDetailsService) {
//        return http.getSharedObject(AuthenticationManagerBuilder.class)
//                .userDetailsService(userDetailsService)
//                .passwordEncoder(passwordEncoder)
//                .
//    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
