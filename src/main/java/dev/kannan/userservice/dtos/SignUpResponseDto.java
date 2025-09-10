package dev.kannan.userservice.dtos;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class SignUpResponseDto {
    private String message;
    private UserDto userDto;
    private ResponseStatus responseStatus;
}
