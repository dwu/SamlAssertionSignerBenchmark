/*
    Based on https://github.com/wayne989/OpenSAML3Example
 */

package org.example.samlutil;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.*;

import java.util.UUID;

public class SamlBuilder {

    public static String destination = "my-destination";

    public static String IDP_ENTITY_ID = "my-awesome-idfs";
    public static String NAME_ID = "my-name";
    public static int validDurationInSeconds = 3600;

    public Response buildResponse() {
        Response samlResponse = SamlUtil.buildSAMLObject(Response.class);
        samlResponse.setDestination(destination);
        DateTime issueInstance = new DateTime();
        String responseID = UUID.randomUUID().toString();
        samlResponse.setID(responseID);
        samlResponse.setIssueInstant(issueInstance);
        samlResponse.setIssuer(getIssuer());
        addStatus(samlResponse);
        return samlResponse;
    }

    public Issuer getIssuer() {
        Issuer issuer = SamlUtil.buildSAMLObject(Issuer.class);
        issuer.setValue(IDP_ENTITY_ID);
        issuer.setFormat(Issuer.ENTITY);
        return issuer;
    }

    public void addStatus(Response samlResponse) {
        Status status = SamlUtil.buildSAMLObject(Status.class);
        StatusCode statusCode = SamlUtil.buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        samlResponse.setStatus(status);
    }

    public Assertion buildAssertion(String id, DateTime issueInstance, String idOne, String idTwo) {
        Assertion assertion = SamlUtil.buildSAMLObject(Assertion.class);
        assertion.setID(id);
        assertion.setIssueInstant(issueInstance);
        assertion.setIssuer(getIssuer());
        assertion.setConditions(buildConditions(issueInstance));
        assertion.setSubject(buildSubject(issueInstance));
        assertion.getAuthnStatements().add(buildAuthnStatement(issueInstance));
        assertion.getAttributeStatements().add(buildAttributeStatement(idOne, idTwo));
        return assertion;
    }

    private Subject buildSubject(DateTime issueInstance) {
        Subject subject = SamlUtil.buildSAMLObject(Subject.class);
        NameID nameID = SamlUtil.buildSAMLObject(NameID.class);
        nameID.setValue(NAME_ID);
        subject.setNameID(nameID);
        subject.getSubjectConfirmations().add(buildSubjectConfirmation(issueInstance));
        return subject;
    }

    private SubjectConfirmation buildSubjectConfirmation(DateTime issueInstance) {
        SubjectConfirmation subjectConfirmation = SamlUtil.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = SamlUtil.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setNotBefore(issueInstance);
        subjectConfirmationData.setNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        subjectConfirmationData.setRecipient(destination);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        return subjectConfirmation;
    }

    private Conditions buildConditions(DateTime issueInstance) {
        Conditions conditions = SamlUtil.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(issueInstance);
        conditions.setNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        AudienceRestriction audienceRestriction = SamlUtil.buildSAMLObject(AudienceRestriction.class);
        Audience audience = SamlUtil.buildSAMLObject(Audience.class);
        audience.setAudienceURI(destination);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }

    private AuthnStatement buildAuthnStatement(DateTime issueInstance) {
        AuthnStatement authnStatement = SamlUtil.buildSAMLObject(AuthnStatement.class);
        AuthnContext authnContext = SamlUtil.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = SamlUtil.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setAuthnInstant(issueInstance);
        authnStatement.setSessionNotOnOrAfter(issueInstance.plusSeconds(validDurationInSeconds));
        return authnStatement;
    }

    private AttributeStatement buildAttributeStatement(String idOne, String idTwo) {
        AttributeStatement attributeStatement = SamlUtil.buildSAMLObject(AttributeStatement.class);
        attributeStatement.getAttributes().add(SamlUtil.buildAttribute("idOne", idOne));
        attributeStatement.getAttributes().add(SamlUtil.buildAttribute("idTwo", idTwo));
        return attributeStatement;
    }

}
