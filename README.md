# OktaTOTPAuthenticator
Burp Suite plugin that dynamically generates Okta TOTP 2FA code for use in session handling rules 

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

<div style='margin-top: 10px; font-size: 12px;'>
<h3 style='text-align: left; font-size: 14px; color: #000;'>How to build jar file using Gradle:</h3>
<ol>
  <li>Clone the repo.</li>
  <li>Install latest version of Gradle, follow the installation instructions <a href="https://gradle.org/install/"> here</a>.</li>
  <li>Once Gradle is installed, run <b>gradle fatJar</b> from the installation directory using the command line.</li>
  <li>Jar file is generated under(../build/libs/OktaAuthenticate-1.0-SNAPSHOT.jar) </li>
</ol>
</div>
                      
