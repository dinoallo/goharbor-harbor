// Copyright 2015 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

// Package schema1 provides the legacy Docker schema 1 parser used by Harbor
// for reading existing manifests. Distribution v3 no longer ships schema 1,
// so the parser is kept as a Harbor compatibility package.
package schema1

import (
	"encoding/json"
	"fmt"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest"
	"github.com/docker/libtrust"
	"github.com/opencontainers/go-digest"
)

const (
	MediaTypeManifest       = "application/vnd.docker.distribution.manifest.v1+json"
	MediaTypeSignedManifest = "application/vnd.docker.distribution.manifest.v1+prettyjws"
	MediaTypeManifestLayer  = "application/vnd.docker.container.image.rootfs.diff+x-gtar"
)

var SchemaVersion = manifest.Versioned{SchemaVersion: 1}

func init() {
	schema1Func := func(b []byte) (distribution.Manifest, distribution.Descriptor, error) {
		sm := new(SignedManifest)
		if err := sm.UnmarshalJSON(b); err != nil {
			return nil, distribution.Descriptor{}, err
		}
		return sm, distribution.Descriptor{
			Digest:    digest.FromBytes(sm.Canonical),
			Size:      int64(len(sm.Canonical)),
			MediaType: MediaTypeSignedManifest,
		}, nil
	}
	for _, mediaType := range []string{MediaTypeSignedManifest, "", "application/json"} {
		if err := distribution.RegisterManifestSchema(mediaType, schema1Func); err != nil {
			panic(fmt.Sprintf("unable to register schema 1 manifest: %s", err))
		}
	}
}

type FSLayer struct {
	BlobSum digest.Digest `json:"blobSum"`
}

type History struct {
	V1Compatibility string `json:"v1Compatibility"`
}

type Manifest struct {
	manifest.Versioned
	Name         string    `json:"name"`
	Tag          string    `json:"tag"`
	Architecture string    `json:"architecture"`
	FSLayers     []FSLayer `json:"fsLayers"`
	History      []History `json:"history"`
}

type SignedManifest struct {
	Manifest
	Canonical []byte `json:"-"`
	all       []byte `json:"-"`
}

func (sm *SignedManifest) UnmarshalJSON(b []byte) error {
	sm.all = append(sm.all[:0], b...)
	jsig, err := libtrust.ParsePrettySignature(b, "signatures")
	if err != nil {
		return err
	}
	payload, err := jsig.Payload()
	if err != nil {
		return err
	}
	sm.Canonical = append(sm.Canonical[:0], payload...)
	var manifest Manifest
	if err := json.Unmarshal(sm.Canonical, &manifest); err != nil {
		return err
	}
	sm.Manifest = manifest
	return nil
}

func (sm SignedManifest) References() []distribution.Descriptor {
	dependencies := make([]distribution.Descriptor, len(sm.FSLayers))
	for i, fsLayer := range sm.FSLayers {
		dependencies[i] = distribution.Descriptor{
			MediaType: MediaTypeManifestLayer,
			Digest:    fsLayer.BlobSum,
		}
	}
	return dependencies
}

func (sm *SignedManifest) MarshalJSON() ([]byte, error) {
	if len(sm.all) > 0 {
		return sm.all, nil
	}
	return json.Marshal(&sm.Manifest)
}

func (sm SignedManifest) Payload() (string, []byte, error) {
	return MediaTypeSignedManifest, sm.all, nil
}

func (sm *SignedManifest) Signatures() ([][]byte, error) {
	jsig, err := libtrust.ParsePrettySignature(sm.all, "signatures")
	if err != nil {
		return nil, err
	}
	return jsig.Signatures()
}
