window.onscroll = function () {
    scrollFunction()
};

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
    window.history.back()

}

function reDirect(url) {
    var ua = navigator.userAgent.toLowerCase(),
        isIE = ua.indexOf('msie') !== -1,
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
        window.location.href = url;
    }
}

if (navigator.userAgent.indexOf('iPhone') != -1) {
    var timeline = document.getElementsByClassName("time-line")[0];;
    timeline.style.display = "none";
}