package konkuk.Shin.global.response;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@JsonPropertyOrder({"success", "status", "message", "data"})
public class BaseResponse<T> {

    private final boolean success;
    private final int code;
    private final String message;
    private final T data;

    private BaseResponse(T data) {
        this.success = true;
        this.code = HttpStatus.OK.value();
        this.message = "요청에 성공하였습니다.";
        this.data = data;
    }

    public static <T> BaseResponse<T> ok(T data) {
        return new BaseResponse<>(data);
    }
}
