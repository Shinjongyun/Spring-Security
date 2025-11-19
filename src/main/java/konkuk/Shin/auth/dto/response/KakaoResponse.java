package konkuk.Shin.auth.dto.response;

import com.umust.dobonglife.domain.auth.model.Provider;
import lombok.RequiredArgsConstructor;

import java.util.Map;

@RequiredArgsConstructor
public class KakaoResponse implements OAuth2Response {

    private final Map<String, Object> attribute;

    @Override
    public Provider getProvider() {
        return Provider.KAKAO;
    }

    @Override
    public String getProviderId() {
        return attribute.get("id").toString();
    }

    @Override
    public String getEmail() {
        return ((Map<String, Object>) attribute.get("kakao_account")).get("email").toString();
    }

    @Override
    public String getName() {
        return ((Map<String, Object>) attribute.get("properties")).get("nickname").toString();
    }
}
