package konkuk.Shin.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
public class LoginResponseDTO {
    String accessToken;
    String refreshToken;
}
