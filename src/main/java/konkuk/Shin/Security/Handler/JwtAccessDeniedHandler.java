package konkuk.Shin.Security.Handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.response.status.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static konkuk.Shin.Common.Util.ErrorResponseUtil.setErrorResponse;

@Component
@RequiredArgsConstructor
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    /**
     * ✅ 인가(Authorization) 실패 시 호출되는 핸들러입니다.
     * - 예: 로그인은 했지만 ROLE_ADMIN 권한이 필요한 요청에 ROLE_USER가 접근할 때
     * - Spring Security가 자동으로 이 메서드를 호출함
     *
     * ✅ ExceptionHandlerFilter는 이 상황을 처리하지 못합니다.
     * - AccessDeniedException은 필터 체인이 아닌 Security 인가 필터 내부에서 발생되므로
     * - try-catch로 잡는 구조가 아닌 Security의 구조적인 처리 대상입니다.
     */
 @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
         setErrorResponse(response, ErrorCode.SECURITY_ACCESS_DENIED);
    }
}
