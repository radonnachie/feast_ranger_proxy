package za.co.discovery.health.bigdata.ranger.feast;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login() {
        System.out.println("LOGGING IN.....");
        return "login";
    }

    @GetMapping("/access-denied")
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String accessDenied() {
        return "access-denied";
    }
}
