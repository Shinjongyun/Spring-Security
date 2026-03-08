package konkuk.Shin.auth.jwt.filter;

import konkuk.Shin.auth.jwt.provider.JwtTokenProvider;
import konkuk.Shin.auth.security.domain.constant.Role;
import konkuk.Shin.auth.security.exception.CustomAuthenticationException;
import konkuk.Shin.auth.security.exception.CustomJwtException;
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

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtStoreService jwtStoreService;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    // 인증을 안해도 되니 토큰이 필요없는 URL들 (에러: 로그인이 필요합니다)
    public final static List<String> PASS_URIS = Arrays.asList(
            "/api/users/signup",
            "/api/auth/login/**",
            "/login/oauth2/**"
    );

    private static final AntPathMatcher ANT = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {

            if (isPassUri(request.getRequestURI())) {
                log.info("JWT Filter Passed (pass uri) : {}", request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }

            // 엑세스 토큰이 없으면 Authentication도 없음 -> EntryPoint (401)
            log.info("Request URI: {}", request.getRequestURI()); // 요청 URI 로깅
            String accessToken = jwtTokenProvider.extractAccessToken(request)
                    .orElseThrow(() -> new CustomAuthenticationException(ErrorCode.SECURITY_UNAUTHORIZED));

            // 엑세스 토큰 유효성 검사
            jwtTokenProvider.validateAccessToken(accessToken);

            // 로그아웃 체크
            jwtStoreService.checkBlacklistedToken(accessToken);

            // 권한 리스트 생성
            List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority(jwtTokenProvider.getRole(accessToken)));
            log.info("Granted Authorities : {}", authorities);
            UserPrincipal principal = UserPrincipal.builder()
                    .userId(jwtTokenProvider.getUserId(accessToken))
                    .userName(jwtTokenProvider.getName(accessToken))
                    .role(Role.fromRole(jwtTokenProvider.getRole(accessToken)))
                    .provider(Provider.fromProvider(jwtTokenProvider.getProvider(accessToken)))
                    .authorities(authorities)
                    .build();
            log.info("UserPrincipal.userId: {}", principal.getUserId());
            log.info("UserPrincipal.userName: {}", principal.getUsername());
            log.info("UserPrincipal.provider: {}", principal.getProvider());
            log.info("UserPrincipal.role: {}", principal.getAuthorities().stream().findFirst().get().toString());

            Authentication authToken = null;
            if ("local".equals(principal.getProvider().getValue())) {
                // 폼 로그인(자체 회원)
                authToken = new UsernamePasswordAuthenticationToken(principal, null, authorities);
            }
            else {
                // 소셜 로그인
                authToken = new OAuth2AuthenticationToken(principal, authorities, principal.getProvider().getValue());
            }
            SecurityContextHolder.getContext().setAuthentication(authToken);

            log.info("Authentication set in SecurityContext: {}", SecurityContextHolder.getContext().getAuthentication());
            log.info("Authorities in SecurityContext: {}", SecurityContextHolder.getContext().getAuthentication().getAuthorities());
            log.info("JWT Filter Success : {}", request.getRequestURI());
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            customAuthenticationEntryPoint.commence(request, response, e);
        }
    }
    private boolean isPassUri(String uri) {
        return PASS_URIS.stream().anyMatch(pattern -> ANT.match(pattern, uri));
    }
}
