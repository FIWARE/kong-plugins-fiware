package org.fiware.kong.pep.model.vc;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class VerifiableCredential {
    public List<String> type;
    @JsonProperty("@context")
    public List<String> context;
    public String id;
    public String issuer;
    public String issuanceDate;
    public String issued;
    public String validFrom;
    public CredentialSchema credentialSchema;
    public CredentialSubject credentialSubject;
    public JWSProof proof;
}
