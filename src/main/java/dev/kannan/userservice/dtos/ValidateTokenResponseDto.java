package dev.kannan.userservice.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ValidateTokenResponseDto {
    private String tokenValue;
    private String nameOfUser;
    private String email;
    private String message;
    private ResponseStatus status;
}
