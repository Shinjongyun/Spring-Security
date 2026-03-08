package konkuk.Shin.security.login;

import com.fasterxml.jackson.databind.ObjectMapper;
import konkuk.Shin.auth.dto.request.FormLoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j
public class CustomLoginFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper;

    public CustomLoginFilter(AuthenticationManager authenticationManager,
                             ObjectMapper objectMapper,
                             AuthenticationSuccessHandler successHandler,
                             AuthenticationFailureHandler failureHandler) {
        this.objectMapper = objectMapper;
        super.setFilterProcessesUrl("/api/auth/login");
        super.setAuthenticationManager(authenticationManager);
        super.setAuthenticationSuccessHandler(successHandler);
        super.setAuthenticationFailureHandler(failureHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        log.info("=== Login Filter (JSON only) 진입 ===");

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            throw new AuthenticationServiceException("지원하지 않는 HTTP 메서드입니다.");
        }

        String contentType = request.getContentType();
        if (contentType == null || !contentType.toLowerCase().contains("application/json")) {
            throw new AuthenticationServiceException("Content-Type application/json 만 허용됩니다.");
        }

        FormLoginRequest login;
        try {
            login = objectMapper.readValue(request.getInputStream(), FormLoginRequest.class);
        } catch (IOException e) {
            throw new AuthenticationServiceException("JSON 파싱 실패", e);
        }

        String email = login.getEmail();
        String password = login.getPassword();

        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            throw new BadCredentialsException("이메일/비밀번호가 비어있습니다.");
        }

        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(email.trim(), password);

        return this.getAuthenticationManager().authenticate(authToken);
    }
}
