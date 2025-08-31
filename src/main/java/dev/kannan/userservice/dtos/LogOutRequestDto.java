package dev.kannan.userservice.dtos;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LogOutRequestDto {
    /*
        - Token object - is an intenal object
        - we will just share the token value
     */
    private String tokenValue;
}
