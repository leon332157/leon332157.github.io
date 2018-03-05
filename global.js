ua = navigator.userAgent.toLowerCase()
isIE = ua.indexOf('msie') !== -1
if (isIE) {
    alert("Please use Google Chrome or Firefox for better view!")
    console.log("IE")
}
window.onscroll = function () {
    scrollFunction()
};
var path = window.location.pathname.split("/");
var path_last = path[path.length - 1];

function scrollFunction() {
    if ($(document).scrollTop() < 20) {
        document.getElementsByClassName("top-button")[0].style.display = "none";
    } else {
        document.getElementsByClassName("top-button")[0].style.display = "block";
    }
}

// When the user clicks on the button, scroll to the top of the document
function topFunction() {
    var head = document.getElementById("html");
    zenscroll.to(head);
}

function Back() {
    reDirect('index.html')
}

function reDirect(url) {
    version = parseInt(ua.substr(4, 2), 10);
    // Internet Explorer 8 and lower
    if (isIE && version < 9) {
        var link = document.createElement('a');
        link.href = url;
        document.body.appendChild(link);
        link.click();
    }
    // All other browsers can use the standard window.location.href (they don't lose HTTP_REFERER like Internet Explorer 8 & lower does)
    else {
        if (url != 'http://www.instagram.com/chenerytrialb') {
            window.location.href = url
        }
        else {
            window.open(url);
        }
    }
}

if (navigator.userAgent.indexOf('iPhone') != -1) {
    var timeline = document.getElementsByClassName("time-line")[0];
    timeline.style.display = "none";
}
var follow = document.getElementById("follow");
var v1 = document.getElementById("v1");
var v2 = document.getElementById("v2");
var twitter_timeline = document.getElementsByClassName("twitter-timeline");
if (twitter_timeline != null) {
    change_href(twitter_timeline)
}

function change_href(object) {
    object.href = "https://twitter.com/Chenerytrial18?ref_src=twsrc%5Etfw";
}

html_width = document.getElementById("html").offsetWidth;
if (follow != null) {
    change_href(follow);
}
var div_width = "width:" + html_width + "px";
var doc_width = $(window).width();
if (v1 != null) {
    document.getElementById("main").style = div_width;
    v1.width = doc_width - 100;
    v1.style.margin = "50px";
    v1.style.alignContent = "center"
}
var doc_width = $(window).width();
if (v2 != null) {
    v2.width = doc_width - 100;
    v2.style.margin = "50px";
    v2.style.alignContent = "center"
}
var sorce = document.createElement("a");
sorce.classList.add("readmore-button");
sorce.href = "https://github.com/leon332157/leon332157.github.io";
sorce.text = "Sorcecode";
sorce.style = "text-decoration: none";
document.body.appendChild(document.createElement("br"));
document.body.appendChild(document.createElement("br"));
document.body.appendChild(sorce);
document.body.appendChild(document.createElement("br"));
document.body.appendChild(document.createElement("br"));
var timeline = document.getElementById("timeline");
if (timeline != null) {
    timeline.setAttribute("data-height", "1000")
}
