/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org)
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

import java.io.IOException;

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

import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.ErrorMessages.AUTH_REQUEST_BUILD_ERROR;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.ErrorMessages.EMPTY_SIGNATURE;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.ErrorMessages.INVALID_SIGNATURE;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.ErrorMessages.LOGIN_PAGE_REDIRECT_ERROR;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.ErrorMessages.URL_BUILDER_ERROR;

import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.LOGIN_TYPE;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.ADDRESS;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.END_POINT_R;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.END_POINT_S;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.LOGIN_PAGE_URL;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.METAMASK_ADDRESS_PREFIX;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.METAMASK_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.METAMASK_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.PERSONAL_PREFIX;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.SERVER_MESSAGE;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.SIGNATURE;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.START_POINT_R;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.START_POINT_S;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.VALID_ECPOINT_POSITION;
import static org.wso2.carbon.identity.metamask.federated.authenticator.MetamaskAuthenticationConstants.VALID_ECPOINT_VALUE;

import java.math.BigInteger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Authenticator of Metamask
 */
public class MetamaskAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return LOGIN_TYPE.equals(getLoginType(request));
    }

    @Override
    public String getFriendlyName() {

        return METAMASK_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return METAMASK_AUTHENTICATOR_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        // Create random message to get metamask signature.
        String serverMessage = RandomStringUtils.randomAlphabetic(10);
        try {
            String authorizationEndPoint = ServiceURLBuilder.create()
                    .addPath(LOGIN_PAGE_URL)
                    .build().getAbsolutePublicURL();
            String state = context.getContextIdentifier() + "," + LOGIN_TYPE;
            OAuthClientRequest authRequest = OAuthClientRequest.authorizationLocation(authorizationEndPoint)
                    .setParameter(SERVER_MESSAGE, serverMessage)
                    .setState(state).buildQueryMessage();
            // Set serverMessage to context.
            context.setProperty(SERVER_MESSAGE, serverMessage);
            // Redirect user to metamask.jsp login page.
            String loginPage = authRequest.getLocationUri();
            response.sendRedirect(loginPage);
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException(URL_BUILDER_ERROR.getCode(),
                    URL_BUILDER_ERROR.getMessage());
        } catch (OAuthSystemException e) {
            throw new AuthenticationFailedException(AUTH_REQUEST_BUILD_ERROR.getCode(),
                    AUTH_REQUEST_BUILD_ERROR.getMessage());
        } catch (IOException e) {
            throw new AuthenticationFailedException(LOGIN_PAGE_REDIRECT_ERROR.getCode(),
                    LOGIN_PAGE_REDIRECT_ERROR.getMessage());
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        // Get the message sent to metamask for sign, in initiateAuthenticationRequest().
        String serverMessage = (String) context.getProperty(SERVER_MESSAGE);
        String metamaskAddress = request.getParameter(ADDRESS);
        String metamaskSignature = request.getParameter(SIGNATURE);
        String addressRecovered;
        if (!metamaskSignature.isEmpty()) {
            addressRecovered = calculatePublicAddressFromMetamaskSignature(serverMessage, metamaskSignature);
        } else {
            throw new AuthenticationFailedException(
                    EMPTY_SIGNATURE.getCode(),
                    EMPTY_SIGNATURE.getMessage());
        }
        // Calculate the recovered address by passing serverMessage and metamaskSignature.
        if (addressRecovered != null && addressRecovered.equals(metamaskAddress)) {
            AuthenticatedUser authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(metamaskAddress);
            context.setSubject(authenticatedUser);
        } else {
            throw new AuthenticationFailedException(
                    INVALID_SIGNATURE.getCode(),
                    INVALID_SIGNATURE.getMessage());
        }
    }

    /**
     * Calculate public address from metamask signature and server generated message.
     *
     * @param serverMessage     The message sent to metamask for getting signature
     * @param metamaskSignature The signature obtained from metamask
     * @return the recovered address from metamask signature using server generated message.
     */
    private static String calculatePublicAddressFromMetamaskSignature(String serverMessage,
                                                                      String metamaskSignature) {

        final String prefix = PERSONAL_PREFIX + serverMessage.length();
        final byte[] msgHash = Hash.sha3((prefix + serverMessage).getBytes());
        final byte[] signatureBytes = Numeric.hexStringToByteArray(metamaskSignature);
        // Get the valid ECDSA curve point(v) from {r,s,v}.
        byte validECPoint = signatureBytes[VALID_ECPOINT_POSITION];
        if (validECPoint < VALID_ECPOINT_VALUE) {
            validECPoint += VALID_ECPOINT_VALUE;
        }
        final Sign.SignatureData signatureData = new Sign.SignatureData(validECPoint,
                Arrays.copyOfRange(signatureBytes, START_POINT_R,
                        END_POINT_R),
                Arrays.copyOfRange(signatureBytes, START_POINT_S,
                        END_POINT_S));
        String addressRecovered = null;
        // Get the public key.
        final BigInteger publicKey =
                Sign.recoverFromSignature(validECPoint - VALID_ECPOINT_VALUE,
                        new ECDSASignature(
                                new BigInteger(1, signatureData.getR()),
                                new BigInteger(1, signatureData.getS())), msgHash);
        if (publicKey != null) {
            // Convert public key into public address.
            addressRecovered = METAMASK_ADDRESS_PREFIX + Keys.getAddress(publicKey);
        }
        return addressRecovered;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String state = request.getParameter(OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    private String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(OAUTH2_PARAM_STATE);
        if (state != null) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        return null;
    }

}
