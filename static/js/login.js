var successPopup = $('#success-popup');
var failurePopup = $('#failure-popup');
var loginBtn = $('#sign-in-button');
successPopup.hide();
failurePopup.hide();

function onLogin(authResult) {
    if (authResult.code) {
        $.ajax({
            type: 'POST',
            url: '/signin?state=' + state,
            data: authResult.code,
            processData: false,
            contentType: 'application/octet-stream; charset=utf-8',
            success: function (result) {
		console.log(result);
                successPopup.text("Login Successful! Redirecting to home...");
                successPopup.show();
                loginBtn.hide();
            },
            error: function (result) {
                failurePopup.text(JSON.stringify(result));
                failurePopup.show(100);
                loginBtn.hide();
            }
        });
    }

}
