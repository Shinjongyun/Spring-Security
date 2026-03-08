package konkuk.Shin.global.error;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@JsonPropertyOrder({"success", "code", "message", "timestamp"})
public class BaseErrorResponse{
    private final boolean success;
    private final int code;
    private final String message;
    private final LocalDateTime timestamp;

    public BaseErrorResponse(ErrorCode code) {
        this.success = false;
        this.code = code.getCode();
        this.message = code.getMessage();
        this.timestamp = LocalDateTime.now();
    }

    public BaseErrorResponse(ErrorCode code, String customMessage) {
        this.success = false;
        this.code = code.getCode();
        this.message = customMessage;
        this.timestamp = LocalDateTime.now();
    }
}
