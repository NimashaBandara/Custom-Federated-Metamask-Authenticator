/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.metamask.federated.authenticator;

import java.util.Arrays;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;
import java.io.*;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import java.math.BigInteger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class MetamaskAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(MetamaskAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return MetamaskAuthenticationConstants.LOGIN_TYPE.equals(getLoginType(request));
    }

    @Override
    public String getFriendlyName() {

        return MetamaskAuthenticationConstants.FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return MetamaskAuthenticationConstants.NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {
        // get the session
        HttpSession session = request.getSession();
        // create random message to get metamask signature
        String serverMessage = RandomStringUtils.randomAlphabetic(10);

        try {

            String authorizationEP = "";
            try {
                authorizationEP = ServiceURLBuilder.create().addPath(MetamaskAuthenticationConstants.LOGIN_PAGE_URL)
                        .build().getAbsolutePublicURL();
            } catch (URLBuilderException e) {

                e.printStackTrace();
            }
            ;
            String state = context.getContextIdentifier() + "," + MetamaskAuthenticationConstants.LOGIN_TYPE;

            OAuthClientRequest authRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
                    .setParameter(MetamaskAuthenticationConstants.SERVER_MESSAGE, serverMessage)
                    .setState(state).buildQueryMessage();
            // set serverMessage to session
            session.setAttribute(MetamaskAuthenticationConstants.SERVER_MESSAGE, serverMessage);

            // redirect user to metamask.jsp login page

            String loginPage = authRequest.getLocationUri();
            response.sendRedirect(loginPage);

        } catch (OAuthSystemException | IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {
        // get the message sent to metamask for sign in initiateAuthenticationRequest()
        HttpSession session = request.getSession(false);
        String serverMessage = (String) session.getAttribute(MetamaskAuthenticationConstants.SERVER_MESSAGE);
        String metamaskAddress = request.getParameter(MetamaskAuthenticationConstants.ADDRESS);
        String metamaskSignature = request.getParameter(MetamaskAuthenticationConstants.SIGNATURE);
        boolean validation = false;
        // call for validate signature from metamask
        validation = validateMetamaskMessageSignature(metamaskAddress, serverMessage, metamaskSignature);

        if (validation) {

            AuthenticatedUser authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(metamaskAddress);
            context.setSubject(authenticatedUser);
        } else {
            log.trace(MetamaskAuthenticationErrorConstants.ErrorMessages.INVALID_SIGNATURE.getMessage());
        }

    }

    // validate metamask signature
    private static boolean validateMetamaskMessageSignature(String metamaskAddress, String serverMessage,
            String metamaskSignature) {
        boolean validationStatus = false;
        final String prefix = MetamaskAuthenticationConstants.PERSONAL_PREFIX + serverMessage.length();
        final byte[] msgHash = Hash.sha3((prefix + serverMessage).getBytes());
        final byte[] signatureBytes = Numeric.hexStringToByteArray(metamaskSignature);
        // get the valid ECDSA curve point(v) from {r,s,v}
        byte validECPoint = signatureBytes[64];
        if (validECPoint < 27) {
            validECPoint += 27;
        }
        final Sign.SignatureData sd = new Sign.SignatureData(validECPoint,
                Arrays.copyOfRange(signatureBytes, 0, 32),
                Arrays.copyOfRange(signatureBytes, 32, 64));
        String addressRecovered = null;
        // get the public key.
        final BigInteger publicKey = Sign.recoverFromSignature(validECPoint - 27, new ECDSASignature(
                new BigInteger(1, sd.getR()),
                new BigInteger(1, sd.getS())), msgHash);
        if (publicKey != null) {
            // convert public key into public address
            addressRecovered = MetamaskAuthenticationConstants.METAMASK_ADDRESS_PREFIX + Keys.getAddress(publicKey);
            if (addressRecovered.equals(metamaskAddress)) {
                validationStatus = true;
            }
        }

        return validationStatus;

    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        String state = request.getParameter(MetamaskAuthenticationConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    private String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(MetamaskAuthenticationConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        return null;
    }

}
