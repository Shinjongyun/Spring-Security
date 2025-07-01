package konkuk.Shin.Oauth2.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.Security.Jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthenticationUtil authenticationUtil;
    // private final CookieUtil cookieUtil;
    private final JwtUtil jwtUtil;
    //private final RedisService redisService;

    @Value("${app.baseUrl}")
    private String baseUrl;
    private static final String LOGIN_SUCCESS_URI = "/api/login/success";

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        String providerId = authenticationUtil.getProviderId();
        String role = authenticationUtil.getRole();
        Long memberId = authenticationUtil.getMemberId();
        log.info("[CustomAuthenticationSuccessHandler] providerId={}, role={}, memberId={}", providerId, role, memberId);

        // 토큰 생성
        String accessToken = jwtUtil.createAccessToken(memberId, providerId, role);
        String refreshToken = jwtUtil.createRefreshToken(memberId, providerId, role);


        //todo
        // refresh token 저장

        // 응답 설정
        response.addCookie(cookieUtil.createCookie("ACCESS_TOKEN", accessToken));
        response.addCookie(cookieUtil.createCookie("REFRESH_TOKEN", refreshToken));

        // 리다이렉션
        response.sendRedirect(baseUrl + LOGIN_SUCCESS_URI);

    }
}

