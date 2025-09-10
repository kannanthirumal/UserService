package dev.kannan.userservice.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignUpRequestDto {
    private String name;
    private String email;
    private String password; //this will be hashed using JWT library and a secret key before getting it saved in the db
}
