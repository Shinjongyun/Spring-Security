package konkuk.Shin.auth.security.exception.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.global.error.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static konkuk.Shin.auth.security.util.AuthErrorResponseUtil.setErrorResponse;


@Slf4j
@Component
public class CustomSessionExpiredStrategy implements SessionInformationExpiredStrategy {

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException {
        log.info("=== CustomSessionExpiredStrategy 진입 ===");
        HttpServletRequest request = event.getRequest();
        HttpServletResponse response = event.getResponse();
        if (response.isCommitted()) {
            log.warn("이미 커밋되었습니다. uri={}", request.getRequestURI());
            return;
        }

        ErrorCode code = ErrorCode.DUPLICATED_LOGIN;
        try {
            setErrorResponse(response, code);
            log.info("중복 로그인이 차단 되었습니다. uri={}", request.getRequestURI());
        } catch (Exception e) {
            log.error("응답에서 오류가 발생했습니다. uri={}", request.getRequestURI(), e);

        }
    }
}