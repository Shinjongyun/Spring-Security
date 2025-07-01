package konkuk.Shin.Domain;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2User implements OAuth2User {

    private final MemberPrincipal memberPrincipal;
//    private final Collection<? extends GrantedAuthority> authorities;

    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                //return Role.fromValue(memberPrincipal.getRole().toString()).toString();
                log.info("[CustomOAuth2User] getAuthority 의 Role = " + memberPrincipal.getRole().toAuthority().toString());
                //return Role.fromValue(memberPrincipal.getRole().toString()).toString();
                //return memberPrincipal.getRole().toAuthority().toString();
                return memberPrincipal.getRole().toAuthority().toString();
            }
        });
        return authorities;

//        return authorities;
    }

    @Override
    public String getName() {
        return memberPrincipal.getName();
    }

    public String getEmail() {
        return memberPrincipal.getEmail();
    }

    public String getProviderId() {
        return memberPrincipal.getProviderId();
    }

    public Long getMemberId() {
        return memberPrincipal.getMemberId();
    }

    // JWT 생성시 이용할 ROLE 이름 반환
    public String getRoleForJwt() {
        return memberPrincipal.getRole().toString();
    }
}