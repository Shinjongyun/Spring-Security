package konkuk.Shin.Auth.Filter;

package konkuk.Shin.Jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.Util.JwtUtil;
import konkuk.Shin.domain.UserEntity;
import konkuk.Shin.dto.LoginRequestDTO;
import konkuk.Shin.dto.LoginResponseDTO;
import konkuk.Shin.service.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    /**
     * 로그인 요청이 오면 이 메서드가 실행됨 (POST /login)
     * - 요청 본문에서 ID/PW 추출
     * - 인증을 시도
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        try {
            // JSON 형식으로 들어온 로그인 요청 파싱
            LoginRequestDTO loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequestDTO.class);

            // Spring Security 인증 토큰 생성
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());

            // 실제 인증 처리 (UserDetailsService → DB 조회 → 비밀번호 검사 등)
            return authenticationManager.authenticate(authToken);

        } catch (IOException e) {
            throw new RuntimeException("로그인 요청 처리 중 오류 발생", e);
        }
    }

    /**
     * 인증 성공 시 호출되는 메서드
     * - JWT 발급
     * - 응답에 AccessToken, RefreshToken 포함
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authentication)
            throws IOException, ServletException {

        // 인증된 사용자 정보 획득
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String username = userDetails.getUsername();
        String role = userDetails.getUser().getRole();

        // JWT 생성
        String accessToken = jwtUtil.createAccessToken(username);
        String refreshToken = jwtUtil.createRefreshToken();

        // refreshToken 저장 (ex: Redis 등)
        jwtUtil.storeRefreshToken(refreshToken, username);

        // 응답 객체 생성
        LoginResponseDTO loginResponse = new LoginResponseDTO(accessToken, refreshToken);

        // 응답 설정 및 반환
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(loginResponse));
    }

    /**
     * 인증 실패 시 호출되는 메서드
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed)
            throws IOException, ServletException {

        // 실패 응답 작성
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // 원하는 커스텀 에러 형식으로 작성 가능
        response.getWriter().write(objectMapper.writeValueAsString(
                new ErrorResponseDTO("LOGIN_FAILED", "이메일 또는 비밀번호가 잘못되었습니다.")
        ));
    }
}
