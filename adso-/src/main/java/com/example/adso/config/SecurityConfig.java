package com.example.adso.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;
import org.springframework.security.config.Customizer;

/**
 * Configuración principal de Spring Security.
 * Define qué rutas están protegidas y cómo.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        private final JwtAuthenticationFilter jwtAuthFilter;
        private final AuthenticationProvider authenticationProvider;

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();

                // CORREGIDO: Se eliminó el '/' extra al final
                configuration.setAllowedOrigins(Arrays.asList("https://practica-frontend-pi.vercel.app"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(Arrays.asList("*"));
                configuration.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(csrf -> csrf.disable())
                                .cors(Customizer.withDefaults()) // Activa la configuración de arriba
                                .authorizeHttpRequests(authz -> authz
                                                // CORREGIDO: Agregado "/" para evitar el error 403 en Render
                                                .requestMatchers(org.springframework.http.HttpMethod.GET,
                                                                "/api/products")
                                                .permitAll() // <-- ¡Cambio aquí!

                                                .requestMatchers(org.springframework.http.HttpMethod.POST,
                                                                "/api/products")
                                                .hasAuthority(com.example.adso.model.Role.ADMIN.name())
                                                .requestMatchers(org.springframework.http.HttpMethod.GET,
                                                                "/api/products")
                                                .hasAnyAuthority(com.example.adso.model.Role.ADMIN.name(),
                                                                com.example.adso.model.Role.USER.name())
                                                .anyRequest().authenticated())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authenticationProvider(authenticationProvider)
                                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }
}