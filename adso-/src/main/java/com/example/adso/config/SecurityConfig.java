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
import com.example.adso.model.Role; // Asegúrate de que esta importación sea correcta

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
        
        // El origen de tu frontend en Vercel
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
            .cors(Customizer.withDefaults()) // Activa la configuración de CORS de arriba
            .authorizeHttpRequests(authz -> authz
                // RUTAS PÚBLICAS (Login y Registro)
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/").permitAll() // Para el chequeo de salud

                // RUTA PROTEGIDA: Crear Producto (SOLO ADMIN)
                .requestMatchers(org.springframework.http.HttpMethod.POST,
                                 "/api/products")
                .hasAuthority(Role.ADMIN.name()) // Requiere el rol ADMIN

                // RUTA PROTEGIDA: Obtener Productos (ADMIN Y USER)
                .requestMatchers(org.springframework.http.HttpMethod.GET,
                                 "/api/products")
                .hasAnyAuthority(Role.ADMIN.name(), Role.USER.name()) // Requiere ADMIN o USER
                
                // TODAS LAS DEMÁS PETICIONES REQUIEREN AUTENTICACIÓN
                .anyRequest().authenticated())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}