package com.nmp.autenticacion.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @name DefaultSecurityConfig
 * @description Clase que tiene finalidad el  habilitar la seguridad
 *
 * @author Uriel P. Ibarra
 * @version 0.1
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Value("${authorization.server.user.name}")
    private String userName;

    @Value("${authorization.server.user.password}")
    private String userPassword;

    @Value("${authorization.server.user.rol}")
    private String userRol;

    /**
     * Metodo que tiene como finalidad autenticar todas las solicitudes
     * @param http objeto para configurar la seguridad
     * @return SecurityFilterChain
     * @throws Exception
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(withDefaults());
        return http.build();
    }

    /**
     * Metodo que nos ayuda  definir a un usuario de ejemplo para la autenticación
     * @return UserDetailsService
     */
    @Bean
    UserDetailsService users() {
        UserDetails user = User.withUsername(userName)
                .passwordEncoder(passwordEncoder()::encode)
                .password(userPassword)
                .roles(userRol)
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    /**
     * Método que nos permite mantener el password de  forma encriptada
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
