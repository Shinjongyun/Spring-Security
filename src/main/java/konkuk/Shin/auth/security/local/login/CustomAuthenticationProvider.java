package konkuk.Shin.auth.security.local.login;

import konkuk.Shin.auth.security.local.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        String rawPassword = (String) authentication.getCredentials();

        log.info("[CustomAuthenticationProvider] 인증 시도: email={}", email);

        // 1. 사용자 조회
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
        if (userDetails == null) {
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
        }

        // 2. 비밀번호 검증
        if (!passwordEncoder.matches(rawPassword, userDetails.getPassword())) {
            log.warn("[CustomAuthenticationProvider] 비밀번호 불일치: email={}", email);
            throw new BadCredentialsException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        log.info("[CustomAuthenticationProvider] 인증 성공: email={}", email);

        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
