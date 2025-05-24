package konkuk.Shin.Auth.Handler;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.Auth.Filter.JwtAuthenticationFilter;
import konkuk.Shin.response.ApiErrorResponse;
import konkuk.Shin.response.status.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;

import static konkuk.Shin.Util.ErrorResponseUtil.setErrorResponse;

@Slf4j
@Component
@AllArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        // 1. 토큰 없음 2. 시그니처(Bearer) 불일치
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            ErrorCode errorCode = ErrorCode.SECURITY_INVALID_TOKEN;
            setErrorResponse(response, ErrorCode.SECURITY_ACCESS_DENIED);
        } else if (authorization.equals(ErrorCode.SECURITY_EXPIRED_TOKEN)) {
            // 3. 토큰 만료
            ErrorCode errorCode = ErrorCode.SECURITY_EXPIRED_TOKEN;
            setErrorResponse(response, ErrorCode.SECURITY_ACCESS_DENIED);
        }
    }
}
