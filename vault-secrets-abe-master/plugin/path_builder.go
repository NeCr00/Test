package abe

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathBuilder(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	entries, err := req.Storage.List(ctx, "")

	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func pathBuilderPath(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("abeEndPoints"),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathBuilder,
			},

			// HelpSynopsis:    pathRoleHelpSyn,
			// HelpDescription: pathRoleHelpDesc,
		},
	}
	// &framework.Path{
	// 	Pattern: "auth",
	// 	Callbacks: map[logical.Operation]framework.OperationFunc{
	// 		logical.ListOperation: b.pathRoleList,
	// 	},

	// 	// HelpSynopsis:    pathRoleHelpSyn,
	// 	// HelpDescription: pathRoleHelpDesc,
	// },
	// &framework.Path{
	// 	Pattern: "auth/" + framework.MatchAllRegex("KEYS"),
	// 	Callbacks: map[logical.Operation]framework.OperationFunc{
	// 		logical.ListOperation: b.pathBuilder,
	// 	},

	// 	// HelpSynopsis:    pathRoleHelpSyn,
	// 	// HelpDescription: pathRoleHelpDesc,
	// },

	// func pathAuthList(b *backend) []*framework.Path {

	// 	return []*framework.Path{
	// 		&framework.Path{
	// 			Pattern: authpath + "/?$",

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ReadOperation: b.handleRead,
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},
	// 		&framework.Path{
	// 			Pattern: authpath + "/KEYS/?$",

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ReadOperation: b.handleRead,
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},
	// 		&framework.Path{
	// 			Pattern: authpath + "/KEYS/" + framework.GenericNameRegex("AUTHORITY") + "/?$",

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ReadOperation: b.handleRead,
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},
	// 		&framework.Path{
	// 			Pattern: authpath + "/KEYS/" + framework.GenericNameRegex("AUTHORITY") + "/" + framework.GenericNameRegex("KEY") + "/?$",

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},
	// 		&framework.Path{
	// 			Pattern: authpath + "/KEYS/" + framework.GenericNameRegex("AUTHORITY") + "/" + framework.GenericNameRegex("KEY") + "/" + framework.GenericNameRegex("DATA_ACCESS") + "/?$",

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ReadOperation: b.handleRead,
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},

	// 		// &framework.Path{
	// 		// 	Pattern: ("auth/KEYS/?$/?$"),

	// 		// 	Callbacks: map[logical.Operation]framework.OperationFunc{
	// 		// 		logical.ReadOperation: b.handleRead,
	// 		// 		logical.ListOperation: b.pathLists,
	// 		// 	},
	// 		// },
	// 	}
	// }

	// func pathGenList(b *backend) []*framework.Path {

	// 	return []*framework.Path{
	// 		&framework.Path{
	// 			Pattern: genpath + "/?$",

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ReadOperation: b.handleRead,
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},
	// 		&framework.Path{
	// 			Pattern: genpath + "/KEYS_GIDS/?$",

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ReadOperation: b.handleRead,
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},
	// 		&framework.Path{
	// 			Pattern: genpath + "/KEYS_GIDS/" + framework.GenericNameRegex("USER"),

	// 			Callbacks: map[logical.Operation]framework.OperationFunc{
	// 				logical.ReadOperation: b.handleRead,
	// 				logical.ListOperation: b.pathList,
	// 			},
	// 		},
	// 	}
	// }
}
