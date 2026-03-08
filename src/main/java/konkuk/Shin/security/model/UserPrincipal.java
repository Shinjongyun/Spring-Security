package konkuk.Shin.security.model;

import com.umust.dobonglife.domain.user.model.Role;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

@Slf4j
@Builder
@Getter
@RequiredArgsConstructor
public class UserPrincipal implements UserDetails, OAuth2User {

    private final Long userId;
    private final String userName;
    private final String password;
    private final Role role;
    private final Provider provider;
    private final Collection<? extends GrantedAuthority> authorities;

    /** UserDetails 구현 */
    @Override
    public String getPassword() { return password; }

    @Override
    public String getUsername() { return userName; }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of();
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }

    @Override
    public String getName() {
        return "";
    }

    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> merged = new LinkedHashSet<>();

        if (this.authorities != null) {
            merged.addAll(this.authorities);
        }

        if (this.role != null) {
            // ROLE_USER / ROLE_ADMIN 형태 보장
            String authority = this.role.toAuthority().toString();
            merged.add(new SimpleGrantedAuthority(authority));
            log.info("[UserPrincipal] merged authority = {}", authority);
        }

        return Collections.unmodifiableSet(merged);
    }
}
