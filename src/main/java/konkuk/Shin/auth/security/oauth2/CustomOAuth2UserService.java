package konkuk.Shin.auth.security.oauth2;

import konkuk.Shin.auth.security.domain.constant.Provider;
import konkuk.Shin.auth.security.domain.entity.UserPrincipal;
import konkuk.Shin.auth.security.oauth2.dto.GoogleResponse;
import konkuk.Shin.auth.security.oauth2.dto.KakaoResponse;
import konkuk.Shin.auth.security.oauth2.dto.OAuth2Response;
import konkuk.Shin.user.domain.entity.User;
import konkuk.Shin.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response;
        log.info("oAuth2User.getAttributes() : {}", oAuth2User.getAttributes());
        switch (registrationId) {
            case "kakao" -> oAuth2Response = new KakaoResponse(oAuth2User.getAttributes());
            case "google" -> oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
            default -> {
                return null;
            }
        }

        Provider provider = oAuth2Response.getProvider();
        String providerId = oAuth2Response.getProvider().getValue() + "_" + oAuth2Response.getProviderId();
        String email =  oAuth2Response.getEmail();
        String name =  oAuth2Response.getName();

        User user = userService.findOrCreateOAuthUser(provider, providerId, email, name);
        return UserPrincipal.builder()
                .userId(user.getId())
                .userName(user.getName())
                .role(user.getRole())
                .provider(provider)
                .authorities(oAuth2User.getAuthorities())
                .build();
    }
}
