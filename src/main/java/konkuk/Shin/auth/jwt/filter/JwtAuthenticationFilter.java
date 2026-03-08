package konkuk.Shin.auth.jwt.filter;

import konkuk.Shin.auth.jwt.exception.JwtExceptionHandlerFilter;
import konkuk.Shin.auth.jwt.provider.JwtTokenProvider;
import konkuk.Shin.auth.security.domain.constant.Role;
import konkuk.Shin.auth.security.exception.CustomAuthenticationException;
import konkuk.Shin.auth.security.exception.handler.CustomAuthenticationEntryPoint;
import konkuk.Shin.auth.security.domain.constant.Provider;
import konkuk.Shin.auth.security.domain.entity.UserPrincipal;
import konkuk.Shin.auth.jwt.service.JwtStoreService;
import konkuk.Shin.global.error.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtStoreService jwtStoreService;

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

        // 토큰이 있으면 검증
        jwtTokenProvider.validateAccessToken(accessToken);
        jwtStoreService.checkBlacklistedToken(accessToken);

        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority(jwtTokenProvider.getRole(accessToken))
        );
        UserPrincipal principal = UserPrincipal.builder()
                .userId(jwtTokenProvider.getUserId(accessToken))
                .userName(jwtTokenProvider.getName(accessToken))
                .role(Role.fromRole(jwtTokenProvider.getRole(accessToken)))
                .provider(Provider.fromProvider(jwtTokenProvider.getProvider(accessToken)))
                .authorities(authorities)
                .build();
        log.info("UserPrincipal.userId: {}", principal.getUserId());

        Authentication authToken = new UsernamePasswordAuthenticationToken(principal, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }
}
