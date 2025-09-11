package dev.kannan.userservice.controllers;

import dev.kannan.userservice.dtos.*;
import dev.kannan.userservice.dtos.ResponseStatus;
import dev.kannan.userservice.exceptions.InvalidTokenException;
import dev.kannan.userservice.models.Token;
import dev.kannan.userservice.models.User;
import dev.kannan.userservice.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequestDto) {
        LoginResponseDto loginResponseDto = new LoginResponseDto();

        try {
            Token token = userService.login(
                    loginRequestDto.getEmail(),
                    loginRequestDto.getPassword()
            );

            loginResponseDto.setToken(token.getValue());
            loginResponseDto.setEmail(token.getUser().getEmail());
            loginResponseDto.setExpiryAt(token.getExpiryAt());
            loginResponseDto.setMessage("User logged in successfully!");
            loginResponseDto.setStatus(ResponseStatus.SUCCESS);

            return ResponseEntity.status(HttpStatus.OK).body(loginResponseDto);
        }
        catch (Exception e) {
            loginResponseDto.setMessage("Error while trying to login! " + e.getMessage());
            loginResponseDto.setStatus(ResponseStatus.FAILURE);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(loginResponseDto);
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponseDto> signUp(@RequestBody SignUpRequestDto signUpRequestDto) {

        SignUpResponseDto signUpResponseDto = new SignUpResponseDto();

        try {
            User user = userService.signup(
                    signUpRequestDto.getName(),
                    signUpRequestDto.getEmail(),
                    signUpRequestDto.getPassword()
            );

            //Convert User to UserDto
            UserDto userDto = UserDto.from(user);
            signUpResponseDto.setUserDto(userDto);
            signUpResponseDto.setMessage("Sign up successful");
            signUpResponseDto.setResponseStatus(ResponseStatus.SUCCESS);

            // Return 201 CREATED with body
            return ResponseEntity.status(HttpStatus.CREATED).body(signUpResponseDto);
        }
        catch (Exception e) {
            //will create a custom exception in production
            signUpResponseDto.setMessage("Sign up failed");
            signUpResponseDto.setResponseStatus(ResponseStatus.FAILURE);

            //log the exception (optional but recommended)
            //e.printStackTrace();

            //return 400 BAD REQUEST with body
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(signUpResponseDto);
        }
    }

    /**
     * we can also make it a delete request
     * ,but I made it a patch req coz I'm soft deleting the record
     * updating the isDeleted boolean field **/
    @PatchMapping("/logout")
    public ResponseEntity<LogOutResponseDto> logOut(@RequestBody LogOutRequestDto logOutRequestDto) {
        LogOutResponseDto response = new LogOutResponseDto();

        try {
            userService.logout(logOutRequestDto.getTokenValue());
            response.setStatus(ResponseStatus.SUCCESS);
            response.setMessage("Logged out successfully");
            return ResponseEntity.ok(response);

        } catch (InvalidTokenException e) {
            response.setStatus(ResponseStatus.FAILURE);
            response.setMessage("Invalid or expired token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);

        } catch (Exception e) {
            response.setStatus(ResponseStatus.FAILURE);
            response.setMessage("Internal server error");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /*
        - I didn't create "ValidateTokenRequestDto"
        - because then I would have to send it in the request body
        - but as per REST guidelines it's not advisable to send a request body for a get request
        - this is not okay right? "public ValidateTokenResponseDto validateToken(@RequestBody ValidateTokenRequestDto validateTokenDto)"
     */
    @GetMapping("/validate-token/{token}")
    public ResponseEntity<ValidateTokenResponseDto> validateToken(@PathVariable("token") String tokenValue) {
        ValidateTokenResponseDto response = new ValidateTokenResponseDto();
        try {
            User user = userService.validateToken(tokenValue);
            response.setEmail(user.getEmail());
            response.setNameOfUser(user.getName());
            response.setMessage("User validated successfully");
            response.setTokenValue(tokenValue);
            response.setStatus(ResponseStatus.SUCCESS);

            return ResponseEntity.status(HttpStatus.OK).body(response);

        }
        catch (InvalidTokenException e) {
            response.setStatus(ResponseStatus.FAILURE);
            response.setMessage("Invalid or expired token");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
        catch (Exception e) {
            response.setStatus(ResponseStatus.FAILURE);
            response.setMessage("Internal server error");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
