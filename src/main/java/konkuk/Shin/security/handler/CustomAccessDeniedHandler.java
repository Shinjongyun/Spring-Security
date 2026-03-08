package konkuk.Shin.security.handler;

import konkuk.Shin.global.error.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static konkuk.Shin.security.util.AuthErrorResponseUtil.setErrorResponse;

@Slf4j
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException{
        log.info("=== AccessDeniedHandler 진입 ===");

        ErrorCode code = ErrorCode.SECURITY_ACCESS_DENIED;
        setErrorResponse(response, code);
    }
}
