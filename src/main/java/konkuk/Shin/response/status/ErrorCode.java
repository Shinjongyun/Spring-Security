package konkuk.Shin.response.status;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

@AllArgsConstructor
public enum ErrorCode implements ResponseStatus {

    // Common
    ILLEGAL_ARGUMENT(100, BAD_REQUEST.value(), "잘못된 요청값입니다."),
    NOT_FOUND(101, HttpStatus.NOT_FOUND.value(), "존재하지 않는 API 입니다."),
    METHOD_NOT_ALLOWED(102, HttpStatus.METHOD_NOT_ALLOWED.value(), "유효하지 않은 Http 메서드입니다."),
    SERVER_ERROR(103, INTERNAL_SERVER_ERROR.value(), "서버에 오류가 발생했습니다."),
    UNAUTHORIZED(104,HttpStatus.UNAUTHORIZED.value(),"인증 자격이 없습니다."),
    FORBIDDEN(105,HttpStatus.FORBIDDEN.value(), "권한이 없습니다."),
    // Auth
    SECURITY_UNAUTHORIZED(600,HttpStatus.UNAUTHORIZED.value(), "인증 정보가 유효하지 않습니다"),
    SECURITY_INVALID_TOKEN(601, HttpStatus.UNAUTHORIZED.value(), "토큰이 유효하지 않습니다."),
    SECURITY_INVALID_REFRESH_TOKEN(602, HttpStatus.UNAUTHORIZED.value(), "refresh token이 유효하지 않습니다."),
    SECURITY_INVALID_ACCESS_TOKEN(603, HttpStatus.UNAUTHORIZED.value(), "access token이 유효하지 않습니다."),
    SECURITY_EXPIRED_TOKEN(604, HttpStatus.UNAUTHORIZED.value(), "토큰이 만료되었습니다. "),
    SECURITY_ACCESS_DENIED(605, HttpStatus.UNAUTHORIZED.value(), "접근 권한이 없습니다."),
    LOGIN_FAILED(606, BAD_REQUEST.value(), "비밀번호가 올바르지 않습니다.");
    @Getter
    private final int code;
    private final int httpStatus;
    private final String message;

    @Override
    public int getHttpStatus() {
        return this.httpStatus;
    }

    @Override
    public String getMessage() {
        return this.message;
    }
}

