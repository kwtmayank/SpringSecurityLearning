package org.learning.SpringSecurityLearning.config;

import org.learning.SpringSecurityLearning.JwtAuthenticationProvider;
import org.learning.SpringSecurityLearning.Utils.JWTUtil;
import org.learning.SpringSecurityLearning.filter.JWTAuthenticationFilter;
import org.learning.SpringSecurityLearning.filter.JWTRefreshFilter;
import org.learning.SpringSecurityLearning.filter.JWTValidationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private JWTUtil jwtUtil;
    private UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(JWTUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(encoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider(jwtUtil, userDetailsService);
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationManager authenticationManager, JWTUtil jwtUtil) throws Exception {

        JWTAuthenticationFilter jwtAuthenticationFilter = new JWTAuthenticationFilter(authenticationManager, jwtUtil);

        JWTValidationFilter jwtValidationFilter = new JWTValidationFilter(authenticationManager);

        JWTRefreshFilter jwtRefreshFilter = new JWTRefreshFilter(jwtUtil, authenticationManager);

        // Configure which paths should be excluded from JWT authentication
        http.authorizeHttpRequests((authorize) ->
                        authorize.requestMatchers("/user/register").permitAll()
                                .anyRequest().authenticated())
                .sessionManagement((sessionManagement) -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(jwtValidationFilter, JWTAuthenticationFilter.class)
                .addFilterAfter(jwtRefreshFilter, JWTValidationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Arrays.asList(daoAuthenticationProvider(),
                jwtAuthenticationProvider()));
    }


//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/user/getUser").hasRole("USER")
//                        .requestMatchers("/admin/**").hasRole("ADMIN")
//                        .requestMatchers("/user/register").permitAll()
//                        .anyRequest().authenticated())
//                .sessionManagement((sessionManagement) -> sessionManagement
//                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
//                        .maximumSessions(1)
//                        .maxSessionsPreventsLogin(true)
//                )
//                .formLogin(Customizer.withDefaults()).
//                headers((headers) -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)); // Added to allow iframe
//        return http.build();
//    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager(
//                User.withUsername("user-one")
//                        .password("{noop}password")
//                        .roles("USER")
//                        .build(),
//                User.withUsername("user-two")
//                .password("{bcrypt}"+ new BCryptPasswordEncoder().encode("password"))
//                .roles("USER")
//                .build()
//        );
//        return userDetailsService;
//    }
}
