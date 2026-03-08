package konkuk.Shin.global.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode{

    // Common
    ILLEGAL_ARGUMENT(100, HttpStatus.BAD_REQUEST.value(), "잘못된 요청값입니다."),
    NOT_FOUND(101, HttpStatus.NOT_FOUND.value(), "존재하지 않는 API 입니다."),
    METHOD_NOT_ALLOWED(102, HttpStatus.METHOD_NOT_ALLOWED.value(), "유효하지 않은 Http 메서드입니다."),
    SERVER_ERROR(103, HttpStatus.INTERNAL_SERVER_ERROR.value(), "서버에 오류가 발생했습니다."),

    // User
    USER_NOT_FOUND(200, HttpStatus.NOT_FOUND.value(), "사용자를 찾을 수 없습니다."),
    USER_DUPLICATE_EMAIL(201, HttpStatus.BAD_REQUEST.value(), "중복된 이메일의 사용자가 있습니다."),
    USER_DUPLICATE_NICKNAME(202, HttpStatus.BAD_REQUEST.value(), "중복된 닉네임의 사용자가 있습니다."),
    USER_MAIL_NOT_FOUND(203, HttpStatus.NOT_FOUND.value(), "해당 이메일의 사용자를 찾을 수 없습니다."),

    // Auth
    SECURITY_UNAUTHORIZED(600,HttpStatus.UNAUTHORIZED.value(), "인증 정보가 유효하지 않습니다"),
    ACCESS_TOKEN_NOT_FOUND(603, HttpStatus.UNAUTHORIZED.value(), "access token을 추출할 수 없습니다."),
    REFRESH_TOKEN_NOT_FOUND(604, HttpStatus.UNAUTHORIZED.value(), "refresh token을 추출할 수 없습니다."),
    SECURITY_ACCESS_DENIED(604, HttpStatus.FORBIDDEN.value(), "접근 권한이 없습니다."),
    INVALID_REFRESH_TOKEN_TYPE(605, HttpStatus.BAD_REQUEST.value(), "refresh token 타입이 유효하지 않습니다."),
    INVALID_ACCESS_TOKEN_TYPE(601, HttpStatus.UNAUTHORIZED.value(), "access token 타입이 유효하지 않습니다."),
    EMPTY_AUTHORIZATION_HEADER(612, HttpStatus.BAD_REQUEST.value(),"Authorization 헤더가 존재하지 않습니다."),
    EXPIRED_ACCESS_TOKEN(613, HttpStatus.UNAUTHORIZED.value(), "이미 만료된 Access 토큰입니다."),
    UNSUPPORTED_TOKEN_TYPE(614, HttpStatus.UNAUTHORIZED.value(),"지원되지 않는 토큰 형식입니다."),
    MALFORMED_TOKEN_TYPE(615, HttpStatus.UNAUTHORIZED.value(),"인증 토큰이 올바르게 구성되지 않았습니다."),
    INVALID_SIGNATURE_JWT(616, HttpStatus.UNAUTHORIZED.value(), "인증 시그니처가 올바르지 않습니다"),
    SECURITY_INVALID_TOKEN(602, HttpStatus.UNAUTHORIZED.value(), "유효하지 않은 토큰입니다."),
    INVALID_EMAIL_OR_PASSWORD(617, HttpStatus.UNAUTHORIZED.value(), "이메일 또는 비밀번호가 올바르지 않습니다."),
    DUPLICATED_LOGIN(621,HttpStatus.UNAUTHORIZED.value(), "다른 기기에서 로그인되어 현재 로그인이 종료되었습니다.");

    private final int code;
    private final int httpStatus;
    private final String message;
}
