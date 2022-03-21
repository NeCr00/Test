package abe

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	cache "github.com/patrickmn/go-cache"
)

// Factory creates a new backend implementing the logical.Backend interface
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(ctx, conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType returns the factory
func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b, err := Backend(ctx, conf)
		if err != nil {
			return nil, err
		}
		b.BackendType = backendType
		if err = b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend returns a new Backend framework struct
func Backend(ctx context.Context, conf *logical.BackendConfig) (*backend, error) {
	var b backend
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{},

			// LocalStorage: []string{
			// 	"/KEYGEN/",
			// 	"/KEYS/",
			// },

			Root: []string{
				"config/*",
			},

			SealWrapStorage: []string{
				coreABEGroupKeyPath,
				AuthoritiesPath + "/*",
				genpath + "/*",
			},
		},

		Paths: framework.PathAppend(
			pathAuthSetup(&b),
			pathAttributes(&b),
			pathKeygenSetup(&b),
			pathEncrypt(&b),
			pathSysDecrypt(&b),
			pathFullDecrypt(&b),
			pathBuilderPath(&b),
		),

		InitializeFunc: b.initializeABE,

		Secrets:     []*framework.Secret{},
	}


	b.abeCache = cache.New(0, 30*time.Second)

	b.crlLifetime = time.Hour * 72
	b.tidyCASGuard = new(uint32)
	b.storage = conf.StorageView

	return &b, nil
}

type backend struct {
	*framework.Backend

	storage      logical.Storage
	abeCache     *cache.Cache
	crlLifetime  time.Duration
	tidyCASGuard *uint32
}

const backendHelp = `
The ABE backend generates...
`
