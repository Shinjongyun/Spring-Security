package konkuk.Shin.auth.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.umust.dobonglife.domain.auth.dto.response.TokenResponse;
import com.umust.dobonglife.domain.auth.service.JwtService;
import com.umust.dobonglife.domain.auth.utils.AuthenticationUtil;
import com.umust.dobonglife.domain.auth.utils.JwtUtil;
import com.umust.dobonglife.global.common.response.BaseResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    private final JwtUtil jwtUtil;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        String provider = authenticationUtil.getProvider();
        String role = authenticationUtil.getRole();
        Long userId = authenticationUtil.getUserId();
        String userName = authenticationUtil.getUserName();
        log.info("[CustomAuthenticationSuccessHandler] provider={}, role={}, userId={}", provider, role, userId);

        // 토큰 생성
        String accessToken = jwtUtil.createAccessToken(userId, provider, role, userName);
        String refreshToken = jwtUtil.createRefreshToken(userId, provider, role);

        // refresh token 저장
        jwtService.storeRefreshToken(refreshToken, userId);
        log.info("[CustomAuthenticationSuccessHandler], refreshToken={}", refreshToken);

        TokenResponse tokenResponse = TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        writeResponse(response, BaseResponse.ok(tokenResponse));
    }

    private void writeResponse(HttpServletResponse response, Object value) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        String body = objectMapper.writeValueAsString(value);
        response.getWriter().write(body);
    }
}
