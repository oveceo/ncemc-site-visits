// Shared auth and API utilities for all pages
(function() {
    'use strict';

    window.api = {
        getToken: function() {
            return localStorage.getItem('auth_token');
        },

        setToken: function(token) {
            localStorage.setItem('auth_token', token);
        },

        clearToken: function() {
            localStorage.removeItem('auth_token');
        },

        isLoggedIn: function() {
            return !!this.getToken();
        },

        requireAuth: function() {
            if (!this.isLoggedIn()) {
                const dest = encodeURIComponent(window.location.pathname + window.location.search);
                window.location.href = '/login.html?next=' + dest;
                return false;
            }
            return true;
        },

        logout: function() {
            const token = this.getToken();
            if (token) {
                fetch(window.API_URL + '/api/logout', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token },
                }).catch(function() {});
            }
            this.clearToken();
            window.location.href = '/login.html';
        },

        fetch: function(path, options) {
            options = options || {};
            var headers = Object.assign({}, options.headers || {});
            var token = this.getToken();
            if (token) {
                headers['Authorization'] = 'Bearer ' + token;
            }
            options.headers = headers;

            var self = this;
            return fetch(window.API_URL + path, options).then(function(r) {
                if (r.status === 401) {
                    self.clearToken();
                    var dest = encodeURIComponent(window.location.pathname);
                    window.location.href = '/login.html?next=' + dest;
                    return Promise.reject(new Error('Unauthorized'));
                }
                return r;
            });
        },

        fetchJSON: function(path, options) {
            return this.fetch(path, options).then(function(r) { return r.json(); });
        },

        postJSON: function(path, body) {
            return this.fetch(path, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            }).then(function(r) { return r.json(); });
        },

        sseUrl: function(path) {
            return window.API_URL + path + (path.includes('?') ? '&' : '?') + 'token=' + (this.getToken() || '');
        },
    };
})();
