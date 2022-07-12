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
    public static final int END_POINT_S= 64;

}