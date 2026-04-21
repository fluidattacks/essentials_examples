// Unsafe: stores HTTP response data in localStorage
const client = new XMLHttpRequest();
client.open("GET", "http://example.com/test", true);

const handler = function () {
    localStorage.setItem("response", this.responseXML);
};

client.onload = handler;

client.onload = function () {
    localStorage.setItem("response", this.responseXML);
};

client.onload = function () {
    localStorage.setItem("userData", this.response);
};

client.onload = function () {
    localStorage.setItem("sessionData", this.responseText);
};

client.send(null);
