package com.films.system.gateway.security;

import jakarta.ws.rs.HttpMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;

import java.util.Arrays;
import java.util.Collections;

@EnableWebFluxSecurity
@Configuration
public class SpringSecurityConfig {

    @Bean
    SecurityWebFilterChain configure(ServerHttpSecurity http, @Autowired JwtAuthoritiesFilter authoritiesFilter) {
        return http
                .authorizeExchange(ex -> {
                    ex.pathMatchers(HttpMethod.GET, "/api/security/oauth/**").permitAll();
                    ex.pathMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll();
                    ex.pathMatchers("/api/films/**").authenticated();
                    ex.anyExchange().permitAll();
                })
                .addFilterAfter(authoritiesFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .addFilterAt(corsFilter(), SecurityWebFiltersOrder.CORS)
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Collections.singletonList("*"));
        corsConfiguration.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

    @Bean
    WebFilter corsFilter() {
        return new CorsWebFilter(corsConfigurationSource());
    }
}
