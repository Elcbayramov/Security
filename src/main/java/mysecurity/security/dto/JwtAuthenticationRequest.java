package mysecurity.security.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class  JwtAuthenticationRequest {

    private String username;
    private String password;

}