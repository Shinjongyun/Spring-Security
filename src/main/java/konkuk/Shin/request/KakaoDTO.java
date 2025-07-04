package konkuk.Shin.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class KakaoDTO {

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OAuthToken {
        private String access_token;
        private String token_type;
        private String refresh_token;
        private int expires_in;
        private String scope;
        private int refresh_token_expires_in;
    }

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class KakaoProfile {
        private Long id;
        private String connected_at;
        private Properties properties;
        private KakaoAccount kakao_account;

        @Getter
        @NoArgsConstructor
        @AllArgsConstructor
        public static class Properties {
            private String nickname;
        }

        @Getter
        @NoArgsConstructor
        @AllArgsConstructor
        public static class KakaoAccount {
            private String email;
            private Boolean is_email_verified;
            private Boolean has_email;
            private Boolean profile_nickname_needs_agreement;
            private Boolean email_needs_agreement;
            private Boolean is_email_valid;
            private Profile profile;

            @Getter
            @NoArgsConstructor
            @AllArgsConstructor
            public static class Profile {
                private String nickname;
                private Boolean is_default_nickname;
            }
        }
    }
}
