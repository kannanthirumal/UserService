package dev.kannan.userservice.dtos;

import dev.kannan.userservice.models.Token;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class LoginResponseDto {
    private String token;
    private String email;
    private Date expiryAt;

    private String message;
    private ResponseStatus status;
}
