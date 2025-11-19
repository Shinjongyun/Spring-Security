package konkuk.Shin.auth.dto.response;

import com.umust.dobonglife.domain.auth.model.Provider;

public interface OAuth2Response {

    Provider getProvider(); // 제공자
    String getProviderId(); // 제공자 부여 Id
    String getEmail();
    String getName();
}
