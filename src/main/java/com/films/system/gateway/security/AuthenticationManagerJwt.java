package com.films.system.gateway.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;

import io.jsonwebtoken.security.Keys;

import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class AuthenticationManagerJwt implements ReactiveAuthenticationManager {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Value("${config.security.oauth.jwt.key}")
    private String jwtKey;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication.getCredentials().toString())
                .map(token -> {
                    final byte[] keyBytes = Decoders.BASE64.decode(jwtKey);
                    final SecretKey key = Keys.hmacShaKeyFor(keyBytes);
                    var payload = Jwts
                        .parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
                    log.info(payload.toString());
                    return payload;
                
                }).map(claims -> {
                    final String username = claims.get("sub", String.class);
                    final List<Map<String, Object>> roles = claims.get("authorities", List.class);
                    final Collection<GrantedAuthority> authorities = roles.stream()
                            .map(authority -> authority.get("authority").toString())
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    return new UsernamePasswordAuthenticationToken(username, null, authorities);
                });
    }
}
