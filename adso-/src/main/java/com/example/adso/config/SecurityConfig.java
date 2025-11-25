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

                configuration.setAllowedOrigins(Arrays.asList("https://practica-frontend-pi.vercel.app"));
                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                configuration.setAllowedHeaders(Arrays.asList("*"));
                configuration.setAllowCredentials(true);
                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration); // Aplica a todas las rutas
                return source;
        }

        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                // Deshabilitamos CSRF (Cross-Site Request Forgery) porque usamos JWT
                                // (stateless)
                                .csrf(csrf -> csrf.disable())

                                .cors(Customizer.withDefaults())

                                // Definimos las reglas de autorización
                                .authorizeHttpRequests(authz -> authz
                                                // Endpoints públicos (registro y login)
                                                .requestMatchers("/", "/api/auth/**").permitAll()

                                                // Endpoints de productos:
                                                // Solo ADMIN puede crear productos (POST)
                                                .requestMatchers(org.springframework.http.HttpMethod.POST,
                                                                "/api/products")
                                                .hasAuthority(com.example.adso.model.Role.ADMIN.name())
                                                // USER y ADMIN pueden ver productos (GET)
                                                .requestMatchers(org.springframework.http.HttpMethod.GET,
                                                                "/api/products")
                                                .hasAnyAuthority(com.example.adso.model.Role.ADMIN.name(),
                                                                com.example.adso.model.Role.USER.name())

                                                // Todas las demás peticiones deben estar autenticadas
                                                .anyRequest().authenticated())

                                // Configuramos la gestión de sesiones como STATELESS (sin estado)
                                // Spring Security no creará ni usará sesiones HTTP.
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // Definimos el proveedor de autenticación
                                .authenticationProvider(authenticationProvider)

                                // Añadimos nuestro filtro de JWT ANTES del filtro estándar de autenticación
                                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }
}
