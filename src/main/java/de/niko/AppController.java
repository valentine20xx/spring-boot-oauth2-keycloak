package de.niko;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

@RestController
public class AppController {

    @RequestMapping("/private")
    public ResponseEntity<String> privateEndpoint(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String username;

        if (principal instanceof DefaultOidcUser defaultOidcUser) {
            username = defaultOidcUser.getPreferredUsername();
        } else {
            username = principal.toString();
        }

        return new ResponseEntity<>("Hello, " + username + "! <a href=\"/logout\">Logout</a>", HttpStatus.OK);
    }

    @RequestMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof AnonymousAuthenticationToken anonymousAuthenticationToken) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof String principalName) {
                return new ResponseEntity<>("public and " + principalName, HttpStatus.OK);
            }
        } else if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
            var oAuth2User = oAuth2AuthenticationToken.getPrincipal();
            var name = oAuth2User.getName();

            return new ResponseEntity<>("public and authenticated:" + name, HttpStatus.OK);
        }


        return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
