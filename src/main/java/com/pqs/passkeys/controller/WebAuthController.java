package com.pqs.passkeys.controller;

import com.pqs.passkeys.web.UserCreateForm;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorImpl;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager;
import com.webauthn4j.springframework.security.exception.WebAuthnAuthenticationException;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.UUIDUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

//@SuppressWarnings("SameReturnValue")
@Controller
@RequiredArgsConstructor
public class WebAuthController {
    private static final String VIEW_HOME = "home";
    private static final String VIEW_LOGIN = "login";
    private final Log logger = LogFactory.getLog(getClass());

    private final WebAuthnAuthenticatorManager webAuthnAuthenticatorManager;

    private final WebAuthnRegistrationRequestValidator registrationRequestValidator;

    @GetMapping(value = "/")
    public String index(Model model) {
        var user = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("user", user);
        return VIEW_HOME;
    }

    @GetMapping(value = "/login")
    public String template(Model model) {
        var userCreateForm = new UserCreateForm();
        var userHandle = Base64UrlUtil.encodeToString(UUIDUtil.convertUUIDToBytes(UUID.randomUUID()));
        userCreateForm.setUserHandle(userHandle);
        model.addAttribute("userForm", userCreateForm);
        return VIEW_LOGIN;
    }

    @PostMapping(value = "/signup")
    public String create(HttpServletRequest request, @Valid @ModelAttribute("userForm") UserCreateForm userCreateForm, BindingResult result, Model model, RedirectAttributes redirectAttributes) {

        try {
            if (result.hasErrors()) {
                model.addAttribute("errorMessage", "Your input needs correction.");
                logger.error("User input validation failed.");

                return VIEW_LOGIN;
            }

            WebAuthnRegistrationRequestValidationResponse registrationRequestValidationResponse;
            try {
                registrationRequestValidationResponse = registrationRequestValidator.validate(
                        request,
                        userCreateForm.getClientDataJSON(),
                        userCreateForm.getAttestationObject(),
                        userCreateForm.getTransports(),
                        userCreateForm.getClientExtensions()
                );
            } catch (WebAuthnException | WebAuthnAuthenticationException e) {
                model.addAttribute("errorMessage", "Authenticator registration request validation failed. Please try again.");
                logger.error("WebAuthn registration request validation failed.", e);
                return VIEW_LOGIN;
            }

            var username = userCreateForm.getUsername();

            var authenticator = new WebAuthnAuthenticatorImpl(
                    "authenticator",
                    username,
                    registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                    registrationRequestValidationResponse.getAttestationObject().getAttestationStatement(),
                    registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getSignCount(),
                    registrationRequestValidationResponse.getTransports(),
                    registrationRequestValidationResponse.getRegistrationExtensionsClientOutputs(),
                    registrationRequestValidationResponse.getAttestationObject().getAuthenticatorData().getExtensions()
            );

            try {
                webAuthnAuthenticatorManager.createAuthenticator(authenticator);
            } catch (IllegalArgumentException ex) {
                model.addAttribute("errorMessage", "Registration failed. The user may already be registered.");
                logger.error("Registration failed.", ex);
                return VIEW_LOGIN;
            }
        } catch (RuntimeException ex) {
            model.addAttribute("errorMessage", "Registration failed by unexpected error.");
            logger.error("Registration failed.", ex);
            return VIEW_LOGIN;
        }

        model.addAttribute("successMessage", "User registration successful. Please login.");
        return VIEW_LOGIN;
    }
}
