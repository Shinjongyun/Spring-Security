package konkuk.Shin.security.oauth2;

import konkuk.Shin.security.model.Provider;

public interface OAuth2Response {

    Provider getProvider(); // 제공자
    String getProviderId(); // 제공자 부여 Id
    String getEmail();
    String getName();
}
