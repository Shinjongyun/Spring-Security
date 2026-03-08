package konkuk.Shin.security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import konkuk.Shin.global.error.BaseErrorResponse;
import konkuk.Shin.global.error.ErrorCode;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class AuthErrorResponseUtil {
    public static final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

    public static void setErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        response.setStatus(errorCode.getHttpStatus());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        BaseErrorResponse errorResponse = new BaseErrorResponse(errorCode);
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
