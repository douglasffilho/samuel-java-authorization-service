package br.com.douglasffilho.authorizationservice.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TokenValidationFilter extends BasicAuthenticationFilter {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String TOKEN_TYPE = "Bearer ";
    private final String token;

    public TokenValidationFilter(AuthenticationManager authenticationManager, final String jwtToken) {
        super(authenticationManager);
        this.token = jwtToken;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        String authToken = req.getHeader(AUTHORIZATION_HEADER);

        if (authToken == null) {
            chain.doFilter(req, res);
            return;
        }

        String token = authToken.replaceAll(TOKEN_TYPE, "");

        DecodedJWT decoded = JWT.require(Algorithm.HMAC512(this.token)).build().verify(token);

        String email = decoded.getClaim("email").asString();

        if (email == null) {
            chain.doFilter(req, res);
            return;
        }

        LocalDateTime expiresAt = LocalDateTime.ofInstant(
                decoded.getExpiresAt().toInstant(),
                ZoneId.of("America/Sao_Paulo")
        );

        if (expiresAt.isBefore(LocalDateTime.now())) {
            chain.doFilter(req, res);
            return;
        }

        String roles = decoded.getClaim("roles").asString();

        if (roles == null || "".equals(roles)) {
            chain.doFilter(req, res);
            return;
        }

        List<GrantedAuthority> authorities = Arrays.
                stream(roles.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                email,
                null,
                authorities
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }
}
