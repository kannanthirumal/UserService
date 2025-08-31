package dev.kannan.userservice.models;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Entity(name = "users")
public class User extends BaseModel{
    private String name;
    private String email;
    private String password;

    @ManyToMany
    private List<Role> roles;
}


/*
    1           M
    User ------ Role => M:N
    M            1

 */
