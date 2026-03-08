package utils_test

import (
	"donow/utils"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieExists(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func() *http.Request
		cookieName string
		want       bool
	}{
		{
			name: "Cookie exists with value",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{
					Name:  "session",
					Value: "abc123",
				})
				return req
			},
			cookieName: "session",
			want:       true,
		},
		{
			name: "Cookie exists but empty value",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{
					Name:  "session",
					Value: "",
				})
				return req
			},
			cookieName: "session",
			want:       false,
		},
		{
			name: "Cookie doesn't exist",
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			cookieName: "session",
			want:       false,
		},
		{
			name: "Different cookie exists",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{
					Name:  "other_cookie",
					Value: "xyz789",
				})
				return req
			},
			cookieName: "session",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			if got := utils.CookieExists(req, tt.cookieName); got != tt.want {
				t.Errorf("CookieExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Standard user agent",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			want:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
		{
			name:      "Mobile user agent",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X)",
			want:      "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X)",
		},
		{
			name:      "Empty user agent",
			userAgent: "",
			want:      "",
		},
		{
			name:      "Bot user agent",
			userAgent: "Googlebot/2.1 (+http://www.google.com/bot.html)",
			want:      "Googlebot/2.1 (+http://www.google.com/bot.html)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", tt.userAgent)

			if got := utils.GetUserAgent(req); got != tt.want {
				t.Errorf("GetUserAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetIP(t *testing.T) {
	tests := []struct {
		name     string
		setupReq func() *http.Request
		want     string
	}{
		{
			name: "IP from X-Forwarded-For",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Forwarded-For", "203.0.113.195")
				// Set RemoteAddr too to ensure X-Forwarded-For takes precedence
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			want: "203.0.113.195",
		},
		{
			name: "Multiple IPs in X-Forwarded-For",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
				return req
			},
			want: "203.0.113.195, 70.41.3.18, 150.172.238.178",
		},
		{
			name: "IP from RemoteAddr",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			want: "192.168.1.1:12345",
		},
		{
			name: "Empty X-Forwarded-For",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Forwarded-For", "")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
			want: "192.168.1.1:12345",
		},
		{
			name: "IPv6 address",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("X-Forwarded-For", "2001:db8:85a3::8a2e:370:7334")
				return req
			},
			want: "2001:db8:85a3::8a2e:370:7334",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			if got := utils.GetIP(req); got != tt.want {
				t.Errorf("GetIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
