// Copyright 2015 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

package challenge

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Octet types from RFC 2616.
type octetType byte

var octetTypes [256]octetType

const (
	isToken octetType = 1 << iota
	isSpace
)

func init() {
	for c := 0; c < 256; c++ {
		var t octetType
		isCtl := c <= 31 || c == 127
		isChar := c <= 127
		isSeparator := strings.ContainsRune(" \t\"(),/:;<=>?@[]\\{}", rune(c))
		if strings.ContainsRune(" \t\r\n", rune(c)) {
			t |= isSpace
		}
		if isChar && !isCtl && !isSeparator {
			t |= isToken
		}
		octetTypes[c] = t
	}
}

// Challenge carries information from a WWW-Authenticate response header.
type Challenge struct {
	Scheme     string
	Parameters map[string]string
}

// Manager manages challenges for registry endpoints.
type Manager interface {
	GetChallenges(endpoint url.URL) ([]Challenge, error)
	AddResponse(resp *http.Response) error
}

// NewSimpleManager returns a manager that maps endpoints to parsed challenges.
func NewSimpleManager() Manager {
	return &simpleManager{Challenges: make(map[string][]Challenge)}
}

type simpleManager struct {
	sync.RWMutex
	Challenges map[string][]Challenge
}

func normalizeURL(endpoint *url.URL) {
	endpoint.Host = strings.ToLower(endpoint.Host)
	endpoint.Host = canonicalAddr(endpoint)
}

func (m *simpleManager) GetChallenges(endpoint url.URL) ([]Challenge, error) {
	normalizeURL(&endpoint)
	m.RLock()
	defer m.RUnlock()
	return m.Challenges[endpoint.String()], nil
}

func (m *simpleManager) AddResponse(resp *http.Response) error {
	challenges := ResponseChallenges(resp)
	if resp.Request == nil {
		return fmt.Errorf("missing request reference")
	}
	urlCopy := url.URL{
		Path:   resp.Request.URL.Path,
		Host:   resp.Request.URL.Host,
		Scheme: resp.Request.URL.Scheme,
	}
	normalizeURL(&urlCopy)
	m.Lock()
	defer m.Unlock()
	m.Challenges[urlCopy.String()] = challenges
	return nil
}

// ResponseChallenges returns the authorization challenges in a 401 response.
func ResponseChallenges(resp *http.Response) []Challenge {
	if resp.StatusCode == http.StatusUnauthorized {
		return parseAuthHeader(resp.Header)
	}
	return nil
}

func parseAuthHeader(header http.Header) []Challenge {
	challenges := []Challenge{}
	for _, h := range header[http.CanonicalHeaderKey("WWW-Authenticate")] {
		v, p := parseValueAndParams(h)
		if v != "" {
			challenges = append(challenges, Challenge{Scheme: v, Parameters: p})
		}
	}
	return challenges
}

func parseValueAndParams(header string) (value string, params map[string]string) {
	params = make(map[string]string)
	value, s := expectToken(header)
	if value == "" {
		return
	}
	value = strings.ToLower(value)
	s = "," + skipSpace(s)
	for strings.HasPrefix(s, ",") {
		var pkey string
		pkey, s = expectToken(skipSpace(s[1:]))
		if pkey == "" || !strings.HasPrefix(s, "=") {
			return
		}
		var pvalue string
		pvalue, s = expectTokenOrQuoted(s[1:])
		if pvalue == "" {
			return
		}
		params[strings.ToLower(pkey)] = pvalue
		s = skipSpace(s)
	}
	return
}

func skipSpace(s string) string {
	i := 0
	for i < len(s) && octetTypes[s[i]]&isSpace != 0 {
		i++
	}
	return s[i:]
}

func expectToken(s string) (token, rest string) {
	i := 0
	for i < len(s) && octetTypes[s[i]]&isToken != 0 {
		i++
	}
	return s[:i], s[i:]
}

func expectTokenOrQuoted(s string) (value, rest string) {
	if !strings.HasPrefix(s, "\"") {
		return expectToken(s)
	}
	s = s[1:]
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[:i], s[i+1:]
		case '\\':
			p := make([]byte, len(s)-1)
			j := copy(p, s[:i])
			escape := true
			for i++; i < len(s); i++ {
				b := s[i]
				switch {
				case escape:
					escape = false
					p[j] = b
					j++
				case b == '\\':
					escape = true
				case b == '"':
					return string(p[:j]), s[i+1:]
				default:
					p[j] = b
					j++
				}
			}
			return "", ""
		}
	}
	return "", ""
}
