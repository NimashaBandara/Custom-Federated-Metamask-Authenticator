<%--
  ~ Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org)
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~You may obtain a copy of the License at
  ~
  ~      http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>
  
  <%@ page import="java.io.File" %>

  <%@ include file="includes/localize.jsp" %>
<jsp:directive.include file="includes/init-url.jsp"/>

<!doctype html>
<html>
<head>
    <!-- header -->
    <%
        File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
        if (headerFile.exists()) {
    %>
        <jsp:include page="extensions/header.jsp"/>
    <% } else { %>
        <jsp:include page="includes/header.jsp"/>
    <% } %>
   
</head>
<body class="login-portal layout authentication-portal-layout">
    <main class="center-segment">    

        <div class="ui container medium center aligned middle aligned">
           
            <%
            File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
            if (productTitleFile.exists()) {
        %>
            <jsp:include page="extensions/product-title.jsp"/>
        <% } else { %>
            <jsp:include page="includes/product-title.jsp"/>
        <% } %>

            <div class="ui segment">
                <h3 class="ui header">Sign In With Metamask</h3>
                <div class="ui divider hidden"></div>
                <div class="ui divider hidden"></div>
                <div class="cookie-policy-message" >
                    <h4> <u>How to Proceed </u></h4>                  
                    <ol> 1. Click **Sign in with Metamask**. </ol>
                    <ol> 2. On the pop-up that appears, select your Metamask account and click **Connect**.</ol>
                    <ol> 3. Finally, click **Sign** to sign the message.</ol>                    
                </div>
                <h1><u></u></h1>
                <div class="field">
                        
                        <button class="ui icon button fluid"
                        onclick="handleNoDomain('metamask','MetamaskAuthenticator')">
                             Sign In With Metamask
                        </button>
                </div>
        </div>
        </div>
    </main>
      <!-- product-footer -->
      <%
      File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
      if (productFooterFile.exists()) {
  %>
      <jsp:include page="extensions/product-footer.jsp"/>
  <% } else { %>
      <jsp:include page="includes/product-footer.jsp"/>
  <% } %>
    <script>

        //function for calling metamask to getting address and signature
       //yet the onboarding metamask is not implemented
       let hasSignature = false
           let verificationStatus = "False"
           let signature = ''
           let address = ''
           let accountOwner={
               userId:'',
               userName:''
           }
       async function metamaskFunction(messageToSign){

           if (window.ethereum && window.ethereum.isMetaMask) {
               console.log("MetaMask Here!");
               await window.ethereum
                   .request({ method: "eth_requestAccounts" })
                   .then(async (result) => {                        
                       address = result[0]
                       console.log('address : ' +address);
                       signature = await window.ethereum.request({
                           method: "personal_sign",
                           params: [messageToSign, address],
                       });
                       hasSignature = true

                   })
           } else {
               console.log("Need to install MetaMask");
               
           }

       }
       let hasclicked=false
       async function handleNoDomain(key,value) {
           
            if (hasclicked) {
                console.warn("Preventing multi click.")
            } else {

            <%
            String state = request.getParameter("state");
            String messageToSign=request.getParameter("serverMessage");
            %>
                await metamaskFunction("<%=messageToSign%>")
                hasclicked=true
              
               //document.location = "<%=commonauthURL%>?idp=" + key + "&authenticator=" + value +"&state="+ "<%=state%>" +"&address="+address+"&signature="+signature;
                //create a form and submit form values to commonauth
                const form = window.document.createElement('form');

                form.setAttribute('action', '<%=commonauthURL%>');

                form.style.display = 'none';

                form.setAttribute('method', 'post');
                const names=["idp","authenticator","state","address","signature"];
                const values=[key,value,"<%=state%>",address,signature];
                for(var i=0; i<names.length;i++){
                    const inpt = window.document.createElement('input');
                    inpt.setAttribute('name', names[i]);
                    inpt.setAttribute('type', 'hidden');
                    inpt.setAttribute('value', values[i]);
                    form.appendChild(inpt);
                }
                window.document.body.appendChild(form);
                form.submit(); 
               
                console.log("form");
            }
       }

    
   </script>
       <!-- footer -->
       <%
       File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
       if (footerFile.exists()) {
   %>
       <jsp:include page="extensions/footer.jsp"/>
   <% } else { %>
       <jsp:include page="includes/footer.jsp"/>
   <% } %>
</body>
</html>
