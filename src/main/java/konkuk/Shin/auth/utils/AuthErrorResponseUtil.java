package konkuk.Shin.auth.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.umust.dobonglife.global.common.response.BaseErrorResponse;
import com.umust.dobonglife.global.common.response.ErrorCode;
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
