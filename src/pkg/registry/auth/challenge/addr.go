// Copyright 2015 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

package challenge

import (
	"net/url"
	"strings"
)

// hasPort reports whether the address includes a port.
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

var portMap = map[string]string{
	"http":  "80",
	"https": "443",
}

// canonicalAddr returns url.Host with a default port when one is not present.
func canonicalAddr(u *url.URL) string {
	addr := u.Host
	if !hasPort(addr) {
		return addr + ":" + portMap[u.Scheme]
	}
	return addr
}
