/*
 * Goi API bang AJAX - tuong ung "Buoc 10: Render in Ajax" (slide 33) trong bai giang.
 *
 * Khac biet so voi bai giang: dung fetch() cua trinh duyet thay cho jQuery, de ung dung
 * khong phu thuoc CDN va chay duoc ca khi khong co Internet. Luong xu ly van giu nguyen:
 *   dang nhap -> luu token vao localStorage -> moi request gan header "Authorization: Bearer <token>".
 *
 * CANH BAO BAO MAT: localStorage khong chong duoc XSS (script chen vao trang co the doc token).
 * Cach lam nay bam sat bai giang; khi lam that nen dung cookie HttpOnly + SameSite, hoac
 * co che refresh token. Xem docs/SECURITY-REVIEW.md.
 */
(function () {
    'use strict';

    var TOKEN_KEY = 'token';

    var API = {
        signup: '/auth/signup',
        login: '/auth/login',
        me: '/users/me'
    };

    var messages = {
        network: 'Khong ket noi duoc may chu.',
        loginFailed: 'Dang nhap that bai.',
        registerFailed: 'Dang ky that bai.',
        sessionExpired: 'Phien dang nhap da het han, vui long dang nhap lai.',
        notLoggedIn: 'Ban chua dang nhap.'
    };

    // ------------------------------ tien ich ------------------------------

    function getToken() {
        return window.localStorage.getItem(TOKEN_KEY);
    }

    function saveToken(token) {
        window.localStorage.setItem(TOKEN_KEY, token);
    }

    function clearToken() {
        window.localStorage.removeItem(TOKEN_KEY);
    }

    function showFeedback(message, isError) {
        var element = document.getElementById('feedback');
        if (!element) {
            return;
        }
        element.textContent = message || '';
        element.classList.toggle('error', Boolean(isError));
        element.classList.toggle('success', Boolean(message) && !isError);
    }

    function jsonHeaders() {
        var headers = { 'Content-Type': 'application/json; charset=utf-8' };
        var token = getToken();
        if (token) {
            headers.Authorization = 'Bearer ' + token;
        }
        return headers;
    }

    /** Doc body thanh JSON neu co the, neu khong thi tra ve text tho. */
    function readBody(response) {
        return response.text().then(function (text) {
            if (!text) {
                return null;
            }
            try {
                return JSON.parse(text);
            } catch (ignored) {
                return text;
            }
        });
    }

    function messageFromBody(body, fallback) {
        if (body && typeof body === 'object') {
            var message = body.description || body.detail || body.title || fallback;

            // Loi validate cua Spring tra ve map "errors" theo tung truong.
            // Hien thi ro truong nao sai de nguoi dung biet can sua gi.
            if (body.errors && typeof body.errors === 'object') {
                var details = Object.keys(body.errors).map(function (field) {
                    return field + ': ' + body.errors[field];
                });
                if (details.length) {
                    message = message + ' -> ' + details.join('; ');
                }
            }
            return message;
        }
        if (typeof body === 'string' && body.trim()) {
            return body;
        }
        return fallback;
    }

    function send(url, options) {
        return fetch(url, options).then(function (response) {
            return readBody(response).then(function (body) {
                if (!response.ok) {
                    var error = new Error(messageFromBody(body, 'HTTP ' + response.status));
                    error.status = response.status;
                    throw error;
                }
                return body;
            });
        });
    }

    // ------------------------------ trang login ------------------------------

    function initLoginPage() {
        var button = document.getElementById('Login');
        if (!button) {
            return;
        }

        clearToken();
        showFeedback('', false);

        button.addEventListener('click', function (event) {
            event.preventDefault();

            var email = document.getElementById('email').value.trim();
            var password = document.getElementById('password').value;

            if (!email || !password) {
                showFeedback('Vui long nhap email va password.', true);
                return;
            }

            send(API.login, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json; charset=utf-8' },
                body: JSON.stringify({ email: email, password: password })
            }).then(function (data) {
                saveToken(data.token);
                window.location.href = '/user/profile';
            }).catch(function (error) {
                showFeedback(messageFromBody(error.message, messages.loginFailed), true);
            });
        });
    }

    // ------------------------------ trang dang ky ------------------------------

    function initRegisterPage() {
        var button = document.getElementById('Register');
        if (!button) {
            return;
        }

        button.addEventListener('click', function (event) {
            event.preventDefault();

            var fullName = document.getElementById('fullName').value.trim();
            var email = document.getElementById('email').value.trim();
            var password = document.getElementById('password').value;

            if (!fullName || !email || !password) {
                showFeedback('Vui long nhap day du ho ten, email va password.', true);
                return;
            }

            send(API.signup, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json; charset=utf-8' },
                body: JSON.stringify({ fullName: fullName, email: email, password: password })
            }).then(function () {
                showFeedback('Dang ky thanh cong, dang chuyen sang trang dang nhap...', false);
                window.setTimeout(function () {
                    window.location.href = '/login';
                }, 900);
            }).catch(function (error) {
                showFeedback(messageFromBody(error.message, messages.registerFailed), true);
            });
        });
    }

    // ------------------------------ trang profile ------------------------------

    function fillProfile(data) {
        document.querySelectorAll('#profile [data-field]').forEach(function (element) {
            var field = element.getAttribute('data-field');
            element.textContent = data[field] === undefined || data[field] === null ? '-' : data[field];
        });

        var avatar = document.getElementById('avatar');
        if (avatar && data.images) {
            avatar.src = data.images;
        }
    }

    function loadProfile() {
        if (!getToken()) {
            window.location.href = '/login';
            return;
        }

        send(API.me, { method: 'GET', headers: jsonHeaders() })
            .then(fillProfile)
            .catch(function (error) {
                if (error.status === 401 || error.status === 403) {
                    clearToken();
                    showFeedback(messages.sessionExpired, true);
                    window.setTimeout(function () {
                        window.location.href = '/login';
                    }, 1200);
                    return;
                }
                showFeedback(messageFromBody(error.message, messages.notLoggedIn), true);
            });
    }

    function initProfilePage() {
        var logout = document.getElementById('logout');
        if (!logout) {
            return;
        }

        logout.addEventListener('click', function () {
            clearToken();
            window.location.href = '/login';
        });

        loadProfile();
    }

    // ------------------------------ khoi dong ------------------------------

    document.addEventListener('DOMContentLoaded', function () {
        initLoginPage();
        initRegisterPage();
        initProfilePage();
    });
})();
