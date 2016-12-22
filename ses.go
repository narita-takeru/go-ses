// Copyright 2013 SourceGraph, Inc.
// Copyright 2011-2013 Numrotron Inc.
// Use of this source code is governed by an MIT-style license
// that can be found in the LICENSE file.

package ses

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type SendOptions struct {
	From string
	Tos  []string
	Ccs  []string
	Bccs []string

	Subject string
	Body    string
}

func (c *Config) SendEmailByOptions(opt SendOptions) (string, error) {

	data := make(url.Values)
	data.Add("Action", "SendEmail")
	data.Add("Source", opt.From)

	for i, to := range opt.Tos {
		seq := 1 + i
		data.Add(fmt.Sprintf("Destination.ToAddresses.member.%d", seq), to)
	}

	for i, cc := range opt.Ccs {
		seq := 1 + i
		data.Add(fmt.Sprintf("Destination.CcAddresses.member.%d", seq), cc)
	}

	for i, bcc := range opt.Bccs {
		seq := 1 + i
		data.Add(fmt.Sprintf("Destination.BccAddresses.member.%d", seq), bcc)
	}

	data.Add("Message.Subject.Data", opt.Subject)
	data.Add("Message.Body.Text.Data", opt.Body)
	//	data.Add("Message.Body.HTML.Data", opt.Body)
	data.Add("AWSAccessKeyId", c.AccessKeyID)

	return sesPost(data, c.Endpoint, c.AccessKeyID, c.SecretAccessKey)
}

// Config specifies configuration options and credentials for accessing Amazon SES.
type Config struct {
	// Endpoint is the AWS endpoint to use for requests.
	Endpoint string

	// AccessKeyID is your Amazon AWS access key ID.
	AccessKeyID string

	// SecretAccessKey is your Amazon AWS secret key.
	SecretAccessKey string
}

// EnvConfig takes the access key ID and secret access key values from the environment variables
// $AWS_ACCESS_KEY_ID and $AWS_SECRET_KEY, respectively.
var EnvConfig = Config{
	Endpoint:        os.Getenv("AWS_SES_ENDPOINT"),
	AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
	SecretAccessKey: os.Getenv("AWS_SECRET_KEY"),
}

// SendRawEmail sends a raw email. Note that from must be a verified address
// in the AWS control panel.
func (c *Config) SendRawEmail(raw []byte) (string, error) {
	data := make(url.Values)
	data.Add("Action", "SendRawEmail")
	data.Add("RawMessage.Data", base64.StdEncoding.EncodeToString(raw))
	data.Add("AWSAccessKeyId", c.AccessKeyID)

	return sesPost(data, c.Endpoint, c.AccessKeyID, c.SecretAccessKey)
}

func authorizationHeader(date, accessKeyID, secretAccessKey string) []string {
	h := hmac.New(sha256.New, []uint8(secretAccessKey))
	h.Write([]uint8(date))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	auth := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s", accessKeyID, signature)
	return []string{auth}
}

func sesGet(data url.Values, endpoint, accessKeyID, secretAccessKey string) (string, error) {
	urlstr := fmt.Sprintf("%s?%s", endpoint, data.Encode())
	endpointURL, _ := url.Parse(urlstr)
	headers := map[string][]string{}

	now := time.Now().UTC()
	// date format: "Tue, 25 May 2010 21:20:27 +0000"
	date := now.Format("Mon, 02 Jan 2006 15:04:05 -0700")
	headers["Date"] = []string{date}

	h := hmac.New(sha256.New, []uint8(secretAccessKey))
	h.Write([]uint8(date))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	auth := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s", accessKeyID, signature)
	headers["X-Amzn-Authorization"] = []string{auth}

	req := http.Request{
		URL:        endpointURL,
		Method:     "GET",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Close:      true,
		Header:     headers,
	}

	r, err := http.DefaultClient.Do(&req)
	if err != nil {
		log.Printf("http error: %s", err)
		return "", err
	}

	resultbody, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if r.StatusCode != 200 {
		log.Printf("error, status = %d", r.StatusCode)

		log.Printf("error response: %s", resultbody)
		return "", errors.New(string(resultbody))
	}

	return string(resultbody), nil
}

func sesPost(data url.Values, endpoint, accessKeyID, secretAccessKey string) (string, error) {
	body := strings.NewReader(data.Encode())
	req, err := http.NewRequest("POST", endpoint, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	now := time.Now().UTC()
	// date format: "Tue, 25 May 2010 21:20:27 +0000"
	date := now.Format("Mon, 02 Jan 2006 15:04:05 -0700")
	req.Header.Set("Date", date)

	h := hmac.New(sha256.New, []uint8(secretAccessKey))
	h.Write([]uint8(date))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	auth := fmt.Sprintf("AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s", accessKeyID, signature)
	req.Header.Set("X-Amzn-Authorization", auth)

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("http error: %s", err)
		return "", err
	}

	resultbody, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	if r.StatusCode != 200 {
		log.Printf("error, status = %d", r.StatusCode)

		log.Printf("error response: %s", resultbody)
		return "", fmt.Errorf("error code %d. response: %s", r.StatusCode, resultbody)
	}

	return string(resultbody), nil
}
