
# Course Project 1 for Cyber Security Base course
## Extremely vulnerable, not to be used in real life!

### The project is a simple web app letting people to sign up for an event
The task was to create a piece of software with at least five flaws from the OWASP Top 10 list and then provide fixes for said flaws

The flaws this piece of software has:
1. Cross-Site Scripting (XSS)
2. Sensitive data exposure
3. Missing function level access control
4. Using components with known vulnerabilities
5. Security misconfiguration

## Cross-Site Scripting (XSS) flaw
1. Start the server
2. Go to ``http://localhost:8080/``
3. Register with a name ``<script> alert("All your base are belong to us!") </script>``
4. Go to ``http://localhost:8080/adminpage/``
4. Now the alert should be shown. The attacker could run all kind of .js on the page!

Issues:
- If an attacker posts a script as a name and/or address to the database, and someone visits the admin page,
  their browser will execute the script.
- So an attacker can execute javascript on the victims' browsers, which is quite alarming. The script might cause
  a redirect to a malicious site, hijack the session, be a some kind of malware etc.
More on this issue at https://www.owasp.org/index.php/Top_10_2013-A3-Cross-Site_Scripting_(XSS)

### One way to fix the problem
Go to ``adminpage.html`` and change utext from the signups to just text. Simple fix! At least this time..


## Sensitive data exposure & Missing function level access control
1. Start the server
2. Go to ``http://localhost:8080/``
3. Register with a name and address
4. Go to ``http://localhost:8080/adminpage/``
5. See the signup information you should not be able to see, as you are not an admin!

Issues:
- Missing function level access control: Access to a site which everybody should not be able to access, the severity of this flaw
  depends what the attacker can exploit by gaining access. In this case there fortunately is not that much the attacker can do.
- Sensitive data exposure: Name & address information displayed, who knows what a devious hacker might do with this information!

### One way to fix the problem
There are multiple ways of fixing this. The simplest is just to disable the adminpage altogether from SignupController.java.
This will get rid of the problem altogether, but it is quite a drastical measure. This solution might affect the business logic side
of things and complicate the life of the admin.. so maybe it is not the ideal solution.
Another way is to add an authentication system, with an admin user/pw combination to grant access to the page. This way the admin
would be able to see who is attending the event, but it would prevent an attacker from gaining the information, if the authentication
system is implemented flawlessly.. so if the developer is up to their tasks, they should find a way to implement a secure authentication system,
which is not affected by all the other vulnerabilities this app has!


## Using components with known vulnerabilities
Vulnerabilities can be checked with Maven Dependency-Check plugin (https://jeremylong.github.io/DependencyCheck/).

1. Get Dependency-Check plugin
2. Run it
3. See what it finds

It should alert that this Spring Boot version has for example a vulnerability
https://nvd.nist.gov/vuln/detail/CVE-2016-9878 which affects certain Spring frameworks (before 3.2.18, 4.2.x before 4.2.9, and 4.3.x before 4.3.5).
Unfortunately our project uses Spring which is one of these unlucky versions!

Issues:
- While this particular vulnerability does not affect the sign up service drastically (afaik), it is not good practice to use outdated software (and there are other vulnerabilities).
- If an attacker can sniff which version of Spring with which plugins and dependencies you are running, they can find vulnerabilities affecting those just by simply googling.
- Difficult to manually go through all the dependencies, so a tool should be used (such as security-check).

### One way to fix the problem and the vulnerability in question
1. Open up the pom.xml file
2. See that Spring Boot is an old 1.4.2. version.
3. Change the dependency to 1.5.9.RELEASE which is the newest version (and hope that it is safe)

- This is a simple fix, you should find a way to keep your software up to date! (and hope that the updates do not break anything..)


## Security misconfiguration
1. Open SecurityConfiguration.java
2. See that the security is effectively disabled
3. Judging by the comments, it seems that the developer has been a bit clumsy, and shipped an unfinished app to production, oops!

Issues:
- If Spring Framework has a security config, why not use it? This leaves the app very vulnerable. Not advisable at all!

### Fix
Maybe one could enable some of the security measures? Enabling https forcing might at least secure the http traffic, and prevent against man-in-the-middle attacks.
Other security measures can also be taken, depending on which the developer finds to be needed, and whether or not an authentication system
is implemented. If the previous issues were fixed with requiring authentication (sensitive user information, unauthorized access), the security package has some tools
that might come handy.
