package konkuk.Shin.user.service;


import jakarta.persistence.EntityNotFoundException;
import konkuk.Shin.global.error.BusinessException;
import konkuk.Shin.global.error.ErrorCode;
import konkuk.Shin.auth.security.domain.constant.Provider;
import konkuk.Shin.auth.security.domain.constant.Role;
import konkuk.Shin.user.domain.entity.User;
import konkuk.Shin.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;

    @Transactional
    public void signUp(SignupRequest request) {
        if (isExistByEmail(request.getEmail())) {
            throw new BusinessException(ErrorCode.USER_DUPLICATE_EMAIL);
        }
        if (!"VERIFIED".equals(mailService.getStoredSignUpCode(request.getEmail()))) {
            throw new BusinessException(ErrorCode.AUTHCODE_UNAUTHORIZED);
        }
        User user = User.builder()
                .email(request.getEmail())
                .name(request.getName())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(Provider.LOCAL)
                .role(Role.MEMBER)
                .build();
        userRepository.save(user);
    }

    @Transactional
    public void deleteAccount(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));

        inValidFcmToken(userId);
        userRepository.delete(user);
        SecurityContextHolder.clearContext();
    }

    @Transactional
    public void updateMyPassword(PasswordUpdateRequest request) {
        User user = userRepository.findByEmailAndProvider(request.getEmail(), Provider.LOCAL)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
        if(user.getPassword() == null){
            throw new BusinessException(ErrorCode.USER_IS_SOCIAL_LOGGED);
        }
        mailService.checkPasswordAuthCode(request.getEmail(), request.getAuthCode());
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
    }

    public boolean validateOwner(Long userId, Long ownerId) {
        if (!userId.equals(ownerId)) {
            return false;
        }
        return true;
    }

    @Transactional
    public User findOrCreateOAuthUser(Provider provider, String providerUserId, String email, String name) {
        return userRepository.findByProviderAndProviderId(provider, providerUserId)
                .orElseGet(() -> reactivateOrCreateOAuthUser(provider, providerUserId, email, name));
    }

    private User reactivateOrCreateOAuthUser(Provider provider, String providerId, String email, String name) {
        // 탈퇴(soft-delete)된 유저가 재가입하는 경우 재활성화
        return userRepository.findInactiveByProviderAndProviderId(provider.name(), providerId)
                .map(inactiveUser -> {
                    inactiveUser.setStatus(BaseStatus.ACTIVE);
                    inactiveUser.setEmail(email);
                    inactiveUser.setBalance(0L);
                    inactiveUser.setDeleteCount(0);
                    inactiveUser.setBlocked(false);
                    inactiveUser.setBlockedAt(null);
                    inactiveUser.setFcmToken(null);
                    inactiveUser.setReceivedAlarm(true);
                    return userRepository.save(inactiveUser);
                })
                .orElseGet(() -> createOAuthUserSafely(provider, providerId, email, name));
    }

    private User createOAuthUserSafely(Provider provider, String providerId, String email, String name) {
        try {
            if(isExistByEmail(email)){
                throw new BusinessException(ErrorCode.USER_DUPLICATE_EMAIL);
            }

            User user = User.builder()
                    .provider(provider)
                    .providerId(providerId)
                    .email(email)
                    .name(name != null ? name : "이름 없는 사용자")
                    .role(Role.MEMBER)
                    .build();

            return userRepository.save(user);

        } catch (DataIntegrityViolationException e) {
            // 동시 로그인 등으로 이미 생성된 경우(유니크 충돌) 재조회해서 반환
            return userRepository.findByProviderAndProviderId(provider, providerId)
                    .orElseThrow(() -> e);
        }
    }

    public User findById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("해당 User 엔티티가 존재하지 않습니다: " + userId));
    }
}

