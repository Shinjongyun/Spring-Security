package konkuk.Shin.response;

import konkuk.Shin.response.status.ResponseStatus;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class ApiErrorResponse {
    private final boolean success;
    private final int status;
    private final String message;
    private final LocalDateTime timestamp;

    public ApiErrorResponse(ResponseStatus status) {
        this.success = false;
        this.status = status.getHttpStatus();
        this.message = status.getMessage();
        this.timestamp = LocalDateTime.now();
    }

    public ApiErrorResponse(ResponseStatus status, String customMessage) {
        this.success = false;
        this.status = status.getHttpStatus();
        this.message = customMessage;
        this.timestamp = LocalDateTime.now();
    }
}
