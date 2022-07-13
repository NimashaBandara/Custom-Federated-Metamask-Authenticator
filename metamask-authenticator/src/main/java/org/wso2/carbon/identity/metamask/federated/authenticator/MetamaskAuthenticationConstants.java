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

public class MetamaskAuthenticationConstants {

    public static final String LOGIN_TYPE = "metamask";
    public static final String METAMASK_AUTHENTICATOR_FRIENDLY_NAME = "Metamask";
    public static final String METAMASK_AUTHENTICATOR_NAME = "MetamaskAuthenticator";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String LOGIN_PAGE_URL = "/authenticationendpoint/metamask.do";
    public static final String PERSONAL_PREFIX = "\u0019Ethereum Signed Message:\n";
    public static final String ADDRESS = "address";
    public static final String SIGNATURE = "signature";
    public static final String SERVER_MESSAGE = "serverMessage";
    public static final String METAMASK_ADDRESS_PREFIX = "0x";
    public static final int VALID_ECPOINT_POSITION = 64;
    public static final int VALID_ECPOINT_VALUE = 27;
    public static final int START_POINT_R = 0;
    public static final int END_POINT_R = 32;
    public static final int START_POINT_S = 32;
    public static final int END_POINT_S = 64;

    public enum ErrorMessages {

        // If the metamask signature is inavlid
        INVALID_SIGNATURE("MET-60000", "Invalid Signature"),
        EMPTY_SIGNATURE("MET-60001", "Empty Signature"),
        URL_BUILDER_ERROR("MET-65001", "Error while building login page URL"),
        LOGIN_PAGE_REDIRECT_ERROR("MET-65002", "Error while redirecting to login page"),
        AUTH_REQUEST_BUILD_ERROR("MET-65003", "Error while building authentication request url");

        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s - %s", code, message);
        }
    }

}