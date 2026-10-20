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
    const jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    localStorage.setItem("userData", jwt_token);
};

client.onload = function () {
    localStorage.setItem("sessionData", this.responseText);
};

client.send(null);
