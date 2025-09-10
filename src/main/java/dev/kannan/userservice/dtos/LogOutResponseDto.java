package dev.kannan.userservice.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LogOutResponseDto {
    private String message;
    private ResponseStatus status;
}
