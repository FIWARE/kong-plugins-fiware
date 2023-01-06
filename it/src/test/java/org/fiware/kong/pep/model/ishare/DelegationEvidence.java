package org.fiware.kong.pep.model.ishare;

import java.util.List;

public class DelegationEvidence {
    public long notBefore;
    public long notOnOrAfter;
    public String policyIssuer;
    public Target target;
    public List<PolicySet> policySets;


}
