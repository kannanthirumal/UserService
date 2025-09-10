package dev.kannan.userservice.models;

import jakarta.persistence.Entity;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity(name = "tokens")
public class Token extends BaseModel {
    private String value;

    @ManyToOne
    private User user;
    private Date expiryAt;
    private boolean isDeleted;

    /* expiry could have been a "Long" datatype as well -> epoch */
    private Long expiry; //epoch
}

/*  1             1
    Token ------- User => M : 1
    M             1
 */
