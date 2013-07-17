package dropbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

var (
	BaseApiUrl     = "api.dropbox.com"
	BaseContentUrl = "api-content.dropbox.com"
	BaseWebUrl     = "www.dropbox.com"

	ApiVersion = 1
)

const (
	GET    = "GET"
	POST   = "POST"
	PUT    = "PUT"
	DELETE = "DELETE"
)

type AuthError struct {
	ErrorText string `json:"error"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Uid         string `json:"uid"`
}

type Session struct {
	AppKey      string
	AppSecret   string
	AccessType  string
	Token       string
	RedirectUri string
}

func buildApiUrl(path string) string {
	return fmt.Sprintf("https://%s/%d/%s", BaseApiUrl, ApiVersion, path)
}

func buildContentApiUrl(path string) string {
	return fmt.Sprintf("https://%s/%d/%s", BaseContentUrl, ApiVersion, path)
}

func buildWebUrl(path string) string {
	return fmt.Sprintf("https://%s/%d/%s", BaseWebUrl, ApiVersion, path)
}

func (e AuthError) Error() string {
	return e.ErrorText
}

func (s *Session) DoRequest(path string, params map[string]string, method string, file []byte) ([]byte, http.Header, error) {
	var buf bytes.Buffer
	buf.WriteString(path)

	if params != nil {
		fmt.Fprintf(&buf, "?")

		for key, val := range params {
			fmt.Fprintf(&buf, "&%s=%s", key, val)
		}
	}

	// access token
	if s.Token != "" {
		if params != nil {
			fmt.Fprintf(&buf, "&access_token=%s", s.Token)
		} else {
			fmt.Fprintf(&buf, "?access_token=%s", s.Token)
		}

	}

	path = buf.String()

	req, err := http.NewRequest(method, path, nil)

	var client http.Client

	if err != nil {
		fmt.Println(err.Error())
		return nil, nil, err
	}

	if file != nil {
		closer := ioutil.NopCloser(bytes.NewReader(file))

		req.Body = closer
		req.ContentLength = int64(len(file))
	}

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println(err.Error())
		return nil, nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	return body, resp.Header, err
}

func (s *Session) MakeContentApiRequest(path string, params map[string]string, method string) (b []byte, h http.Header, e error) {
	b, h, e = s.DoRequest(buildContentApiUrl(path), params, method, nil)
	return
}

func (s *Session) MakeApiRequest(path string, params map[string]string, method string) (b []byte, h http.Header, e error) {
	b, h, e = s.DoRequest(buildApiUrl(path), params, method, nil)
	return
}

func (s *Session) MakeUploadRequest(path string, params map[string]string, method string, file []byte) (b []byte, h http.Header, e error) {
	b, h, e = s.DoRequest(buildContentApiUrl(path), params, method, file)
	return
}

func (s *Session) ObtainToken(code string) (token string, uid string, err error) {
	path := fmt.Sprintf("oauth2/token?code=%s&grant_type=authorization_code&client_secret=%s&client_id=%s&redirect_uri=%s", code, s.AppSecret, s.AppKey, s.RedirectUri)

	body, _, err := s.MakeApiRequest(path, nil, POST)

	if err != nil {
		return "", "", err
	}

	var tokenresp TokenResponse

	err = json.Unmarshal(body, &tokenresp)

	if err != nil {
		return "", "", err
	}

	return tokenresp.AccessToken, tokenresp.Uid, nil
}

func GenerateAuthorizeUrl(clientId string, p *Parameters) (r string) {
	r = fmt.Sprintf("%s?client_id=%s&response_type=code", buildWebUrl("oauth2/authorize"), clientId)

	var buf bytes.Buffer
	buf.WriteString(r)

	if p != nil {
		if p.RedirectUri != "" {
			fmt.Fprintf(&buf, "&redirect_uri=%s", p.RedirectUri)
		}

		if p.Locale != "" {
			fmt.Fprintf(&buf, "&locale=%s", p.Locale)
		}
	}

	r = buf.String()

	return
}
