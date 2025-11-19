package konkuk.Shin.auth.filter;

import com.umust.dobonglife.domain.auth.exception.CustomAuthenticationException;
import com.umust.dobonglife.domain.auth.exception.CustomJwtException;
import com.umust.dobonglife.domain.auth.exception.handler.CustomAuthenticationEntryPoint;
import com.umust.dobonglife.domain.auth.model.Provider;
import com.umust.dobonglife.domain.auth.model.UserPrincipal;
import com.umust.dobonglife.domain.auth.service.JwtService;
import com.umust.dobonglife.domain.auth.utils.JwtUtil;
import com.umust.dobonglife.domain.user.model.Role;
import com.umust.dobonglife.global.common.response.ErrorCode;
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
    private final JwtUtil jwtUtil;
    private final JwtService jwtService;
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
            String accessToken = jwtUtil.extractAccessToken(request)
                    .orElseThrow(() -> new CustomAuthenticationException(ErrorCode.SECURITY_UNAUTHORIZED));

            // 토큰 유효성 검사
            jwtUtil.validateToken(accessToken);

            // 토큰 타입 검사
            if (!"access".equals(jwtUtil.getTokenType(accessToken))) {
                throw new CustomJwtException(ErrorCode.INVALID_TOKEN_TYPE);
            }

            // 로그아웃 체크
            jwtService.checkLogout(accessToken);

            // 권한 리스트 생성
            List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority(jwtUtil.getRole(accessToken)));
            log.info("Granted Authorities : {}", authorities);
            UserPrincipal principal = UserPrincipal.builder()
                    .userId(jwtUtil.getUserId(accessToken))
                    .userName(jwtUtil.getName(accessToken))
                    .role(Role.fromRole(jwtUtil.getRole(accessToken)))
                    .provider(Provider.fromProvider(jwtUtil.getProvider(accessToken)))
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
