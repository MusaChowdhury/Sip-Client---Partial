# About
 SIP client (partially developed) for collecting/identifying caller Id/Extension over SIP protocol.
<br>
<br>

# Why?
The purpose of this project is to get incoming caller ID from the SIP server. As this program does not have any dependencies except Python itself, using this automation task can be done.
<br>
For example, there are certain tasks that need to be done if only Person "A" calls Person "B". Now, while A calls B, there needs to be a way to know B's call list in real time.
<br>
As our concern is only Caller ID/Number, using this program and configuring the Sip server's dial plan, we can get B's call list in real time.
<br>
<br>

# Steps To Use
To track an extension's call list in real time,
<ol>
<li>Create a new extension.</li>
<li>Configure the SIP client with the newly created extension's credentials.</li>
<li>Configure the dial plan of the extension that is going to be tracked.
<br>
For example, if the new extension ID is 200 and the target is to track extension ID 100, then go to the dialplan of 100 and add "
PJSIP/100 && PJSIP/200". (considering the sip server is asterisk/freepbx)</li>
<li>Add a callback function according to requirement.</li>
</ol>
<br>
<br>

# Limitations
<ul>
<li>Only works if the SIP server and the program are running in the same network.</li>
<li>Only capability is to parse the caller ID from the incoming header.</li>
<li>Only supports UDP.</li>
</ul>
<br>
<br>