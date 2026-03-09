package konkuk.Shin.global.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import konkuk.Shin.global.resolver.CurrentUserId;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SwaggerConfig {

    static {
        org.springdoc.core.utils.SpringDocUtils.getConfig().addAnnotationsToIgnore(
                CurrentUserId.class
        );
    }

    @Bean
    public OpenAPI openAPI() {
        List<Server> servers = new ArrayList<>();

        servers.add(new Server()
                .url("http://localhost:8080")
                .description("로컬 개발 서버"));

        Components components = new Components()
                .addSecuritySchemes("BearerAuth",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Access Token: Authorization 헤더에 Bearer {accessToken}"));

        return new OpenAPI()
                .components(components)
                .info(apiInfo())
                .servers(servers)
                .addSecurityItem(new SecurityRequirement().addList("BearerAuth"));
    }


    private Info apiInfo() {
        return new Info()
                .title("Jwt & Security (Spring Doc)")
                .description("Jwt와 Security 학습용 API 가이드")
                .version("1.0.0");
    }
}
