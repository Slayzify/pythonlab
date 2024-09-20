A basic File Interceptor that sniffs traffic on port 80 and monitors for any executables download.
Replaces the initial executable from the remote legit site with a reverse shell or credential harvester.

Improvements:
- Find a way to serve the initial filename instead our malicious filename executable to make it more "realistic".
