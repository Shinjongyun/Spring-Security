package konkuk.Shin.auth.security.oauth2.dto;

import konkuk.Shin.auth.security.domain.constant.Provider;

public interface OAuth2Response {

    Provider getProvider(); // 제공자
    String getProviderId(); // 제공자 부여 Id
    String getEmail();
    String getName();
}
