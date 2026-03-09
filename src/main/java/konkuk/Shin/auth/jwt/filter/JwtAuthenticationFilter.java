package konkuk.Shin.auth.jwt.filter;

import io.jsonwebtoken.Claims;
import konkuk.Shin.auth.jwt.provider.JwtTokenProvider;
import konkuk.Shin.auth.security.domain.constant.Role;
import konkuk.Shin.auth.security.domain.constant.Provider;
import konkuk.Shin.auth.security.domain.entity.UserPrincipal;
import konkuk.Shin.auth.jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("JWT Filter Request URI: {}", request.getRequestURI());

        Optional<String> optionalAccessToken = jwtTokenProvider.extractAccessToken(request);

        // 토큰이 없으면 그냥 통과
        if (optionalAccessToken.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = optionalAccessToken.get();

        // 토큰 검증 + Claims 한 번만 파싱
        Claims claims = jwtTokenProvider.validateAccessToken(accessToken);
        jwtService.checkBlacklistedToken(accessToken);

        String role = jwtTokenProvider.getRole(claims);
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));
        UserPrincipal principal = UserPrincipal.builder()
                .userId(jwtTokenProvider.getUserId(claims))
                .userName(jwtTokenProvider.getName(claims))
                .role(Role.fromRole(role))
                .provider(Provider.fromProvider(jwtTokenProvider.getProvider(claims)))
                .authorities(authorities)
                .build();
        log.info("UserPrincipal.userId: {}", principal.getUserId());

        Authentication authToken = new UsernamePasswordAuthenticationToken(principal, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }
}
