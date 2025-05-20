package com.pqs.passkeys.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Set;

@Data
public class UserCreateForm {

    @NotNull
    private String userHandle;

    @NotEmpty
    private String username;

    @NotNull
    @Valid
    private String clientDataJSON;

    @NotNull
    @Valid
    private String attestationObject;

    private Set<String> transports;

    @NotNull
    private String clientExtensions;
}
