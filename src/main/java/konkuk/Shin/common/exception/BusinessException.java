package konkuk.Shin.common.exception;


import com.umust.dobonglife.global.common.response.ErrorCode;
import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {
    private final ErrorCode errorCode;

    public BusinessException(ErrorCode code) {
        super(code.getMessage());
        this.errorCode = code;
    }
}