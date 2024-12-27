# OktaTOTPAuthenticator
Burp Suite plugin that dynamically generates Okta TOTP 2FA code for use in session handling rules.

<div style='margin-top: 10px; font-size: 12px;'>
                        <h3 style='text-align: left; font-size: 14px; color: #000;'>How to Configure:</h3>
                         <ol>
                              <li>Load the extension into <b>Extensions > Installed > Add > Extension Type: Java > Choose the jar file</b></li>
                           <li> Go to <b>Okta TOTP Authenticator</b> UI interface - Either <b>Import QR</b> or manually update sharedsecret value in <b>Shared Secret</b> field, click on 'Update' button and update Regex Pattern </li>                            
                              <li>Go to <b>Settings > Search > Sessions</b></li>
                              <li>Under <b>Session handling rules</b>, go to <b>Add > Rule actions > Add > Invoke a Burp extension</b>,<br>
                                  select '<b>Okta TOTP Handler</b>' from the dropdown list available and click OK.</li>
                              <li>Click across to the <b>Scope</b> tab, ensuring that the <b>Tools scope > Scanner, Repeater</b> box is checked.</li>                            
                              <li>Configure the URL scope appropriately. Click OK.</li>
                              <li>Now you can perform security testing on Okta enabled authentication sites in Burp Suite Professional.</li>
                         </ol>
                     </div> 
                                        
**Regex Pattern:** (?<![\w\d])\d{6,8}(?![\w\d])

<img width="665" alt="image" src="https://github.com/user-attachments/assets/5d8ef0e5-2c7b-4cd6-902e-ab66d1e43ceb" />

<img width="665" alt="image" src="https://github.com/user-attachments/assets/d9b4e2d3-2348-4859-a9a3-663ee6df9f11" />

The Okta TOTP Authenticator extension integrates seamlessly with Burp Suite Pro to:
<ol>
<li>Handle TOTP generation for Okta accounts.</li>
<li>Inject generated TOTP codes dynamically into HTTP requests.</li>
<li>Simplify workflows by allowing users to upload QR codes or manually configure shared secrets.</li>
<li>Support regex-based customization to identify where TOTP codes should be injected.</li>
</ol>

**Features of the Extension**
1. QR Code Upload for Shared Secret Extraction
The extension allows users to upload a QR code associated with their Okta account. It decodes the QR code, extracts the shared secret, and securely stores it in Base64 format.
2. Manual Configuration of Shared Secret
For scenarios where a QR code is unavailable, the shared secret can be manually entered and updated directly in the extension's user interface (UI).
3. TOTP Code Display and Refresh
The generated TOTP code is prominently displayed in the UI and refreshes every 30 seconds to align with the TOTP protocol.
4. Regex-Based Request Matching
Users can specify a regex pattern to identify where TOTP codes need to be injected in HTTP requests. The default regex can be customized via the UI.
5. Session Handling Automation
The extension integrates with Burp Suite's session handling rules, enabling automatic TOTP injection into requests without manual intervention.

<div style='margin-top: 10px; font-size: 12px;'>
<h3 style='text-align: left; font-size: 14px; color: #000;'>How to build jar file using Gradle:</h3>
<ol>
  <li>Clone the repo.</li>
  <li>Install latest version of Gradle, follow the installation instructions <a href="https://gradle.org/install/"> here</a>.</li>
  <li>Once Gradle is installed, run <b>gradle fatJar</b> from the installation directory using the command line.</li>
  <li>Jar file is generated under(../build/libs/OktaAuthenticate-1.0-SNAPSHOT.jar) </li>
</ol>
</div>
                      
