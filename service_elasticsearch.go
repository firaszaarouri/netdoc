package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Elasticsearch / OpenSearch version probe. Plain HTTP/1.0 GET / and parse the
// root JSON. Pre-8.x ES returns version + cluster_name anonymously; 8.x+ with
// security-by-default returns 401 with `WWW-Authenticate: Basic realm="security"`
// which is itself a strong fingerprint.
//
// Reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/

func probeElasticsearch(addr, host string, timeout time.Duration) serviceInfo {
	info := serviceInfo{Product: "Elasticsearch"}
	conn, err := dialProbe(addr, timeout)
	if err != nil {
		return serviceInfo{}
	}
	defer conn.Close()

	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: netdoc\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return info
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return info
	}
	defer resp.Body.Close()

	auth := resp.Header.Get("WWW-Authenticate")
	switch resp.StatusCode {
	case 401:
		if strings.Contains(strings.ToLower(auth), "elasticsearch") || strings.Contains(strings.ToLower(auth), "realm=\"security\"") {
			info.Extra = map[string]string{"auth": "required", "www_authenticate": auth}
			info.Banner = "401 Unauthorized · " + auth
			return info
		}
		info.Product = ""
		return info
	case 200:
		// fall through
	default:
		info.Banner = resp.Status
		return info
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return info
	}
	var doc struct {
		Name        string `json:"name"`
		ClusterName string `json:"cluster_name"`
		Version     struct {
			Number        string `json:"number"`
			LuceneVersion string `json:"lucene_version"`
			Distribution  string `json:"distribution"`
			BuildHash     string `json:"build_hash"`
			BuildType     string `json:"build_type"`
		} `json:"version"`
		Tagline string `json:"tagline"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		info.Product = ""
		end := 64
		if len(body) < end {
			end = len(body)
		}
		info.Banner = string(body[:end])
		return info
	}
	if doc.Version.Distribution == "opensearch" {
		info.Product = "OpenSearch"
	}
	info.Version = doc.Version.Number
	info.Extra = map[string]string{"auth": "open"}
	if doc.ClusterName != "" {
		info.Extra["cluster"] = doc.ClusterName
	}
	if doc.Version.LuceneVersion != "" {
		info.Extra["lucene"] = doc.Version.LuceneVersion
	}
	if doc.Tagline != "" {
		info.Extra["tagline"] = doc.Tagline
	}
	if doc.Name != "" {
		info.Extra["node_name"] = doc.Name
	}
	info.Banner = doc.Tagline
	return info
}
