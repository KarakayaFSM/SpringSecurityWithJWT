package com.example.demo.security.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Nonnull;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest httpServletRequest,
                                    @Nonnull HttpServletResponse httpServletResponse,
                                    @Nonnull FilterChain filterChain)
            throws ServletException, IOException {

        String authorizationHeader =
                getAuthHeader(httpServletRequest);

        if (!isHeaderValid(authorizationHeader)) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        try {
            Jws<Claims> claimsJws = getClaimsJws(authorizationHeader);

            // type comes from the actual JWT body structure
            // list of singleton maps
            var authorities = getAuthorities(claimsJws);

            var grantedAuthorities =
                    grantedAuthoritiesFrom(authorities);

            Authentication authentication =
                    getAuthentication(claimsJws, grantedAuthorities);

            setContextAuthentication(authentication);

        } catch (JwtException e) {
            String token = deletePrefix(authorizationHeader);
            throw new IllegalStateException("Token cannot be validated:\n" + token);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void setContextAuthentication(Authentication authentication) {
        SecurityContextHolder
                .getContext()
                .setAuthentication(authentication);
    }

    private List<Map<String, String>> getAuthorities(Jws<Claims> claimsJws) {
        //noinspection unchecked
        return (List<Map<String, String>>)
                claimsJws
                        .getBody().get("authorities");
    }

    private Authentication getAuthentication(Jws<Claims> claimsJws,
                                             Set<SimpleGrantedAuthority> grantedAuthorities) {
        return new UsernamePasswordAuthenticationToken(
                claimsJws.getBody().getSubject(),
                null,
                grantedAuthorities
        );
    }

    private Set<SimpleGrantedAuthority> grantedAuthoritiesFrom(List<Map<String, String>> authorities) {
        return authorities
                .stream()
                .map(authorityMap ->
                        new SimpleGrantedAuthority(authorityMap.get("authority"))
                )
                .collect(Collectors.toSet());
    }

    private Jws<Claims> getClaimsJws(String authorizationHeader) {
        String token = deletePrefix(authorizationHeader);

        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);
    }

    private String deletePrefix(String authorizationHeader) {
        return authorizationHeader
                .replace(jwtConfig.getTokenPrefix(), "");
    }

    private boolean isHeaderValid(String authorizationHeader) {
        return !(Strings.isNullOrEmpty(authorizationHeader) ||
                !authorizationHeader
                        .startsWith(jwtConfig.getTokenPrefix()));
    }

    private String getAuthHeader(HttpServletRequest httpServletRequest) {
        return httpServletRequest
                .getHeader(jwtConfig
                        .getAuthorizationHeader()
                );
    }
}
