package konkuk.Shin.Security.Handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.response.status.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;

import static konkuk.Shin.Common.Util.ErrorResponseUtil.setErrorResponse;

@Slf4j
@Component
@AllArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException{
        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        ErrorCode errorCode;
        if (authorization == null || authorization.isBlank()) {
            // 토큰 자체가 없음
            errorCode = ErrorCode.TOKEN_NOT_EXIST;
        } else if (!authorization.startsWith("Bearer ")) {
            // Bearer 접두어 없음
            errorCode = ErrorCode.SECURITY_INVALID_TOKEN;
        } else {
            // 형식은 맞는데 인증 실패 → 만료 또는 기타 사유
            errorCode = ErrorCode.SECURITY_INVALID_TOKEN;
        }
        setErrorResponse(response, errorCode);
    }
}
