package konkuk.Shin.Security.Filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.security.auth.message.AuthException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.response.status.ErrorCode;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.security.sasl.AuthenticationException;
import java.io.IOException;
import java.nio.file.AccessDeniedException;

import static konkuk.Shin.Common.Util.ErrorResponseUtil.setErrorResponse;

// JWT 인증 필터에서 발생한 예외 처리 전담
public class JwtExceptionHandlerFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);

        } catch (AuthException e) {
            setErrorResponse(response, e.getErrorCode());

        } catch (ExpiredJwtException e) {
            setErrorResponse(response, ErrorCode.SECURITY_INVALID_TOKEN);

        } catch (UnsupportedJwtException | MalformedJwtException | SignatureException |
                 PrematureJwtException | MissingClaimException | IncorrectClaimException e) {
            setErrorResponse(response, ErrorCode.SECURITY_UNAUTHORIZED);

        } catch (AuthenticationException e) {
            setErrorResponse(response, ErrorCode.SECURITY_UNAUTHORIZED);

        } catch (AccessDeniedException e) {
            setErrorResponse(response, ErrorCode.SECURITY_ACCESS_DENIED);

        } catch (JwtException e) {
            // 위에 포함되지 않은 JWT 관련 예외도 커버
            setErrorResponse(response, ErrorCode.SECURITY_UNAUTHORIZED);

        } catch (Exception e) {
            setErrorResponse(response, ErrorCode.SERVER_ERROR);
        }
    }
}
