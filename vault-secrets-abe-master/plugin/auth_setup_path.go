package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAuthSetup(b *backend) []*framework.Path {

	return []*framework.Path{
		{
			Pattern: framework.GenericNameRegex("authorityName") + "/addattributes",

			Fields: map[string]*framework.FieldSchema{
				"authorityAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "An array with the names of the Authority attributes (e.g. `authorityAttributes: [`a_attr1`,...`a_attrN`]`",
					Required:    true,
				},
				"commonAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "An array with the names of the Common attributes (e.g. `commonAttributes: [`c_attr1`,...`c_attrN`]`",
					Required:    true,
				},
				"authorityName": {
					Type:        framework.TypeString,
					Description: "The authority's name that adds the new attributes",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.authSetup,
				logical.CreateOperation: b.authSetup,
			},
		},
		{
			Pattern: AuthoritiesPath + "/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: AuthoritiesPath + "/" + framework.GenericNameRegex("ENTITYORATTRIBUTE") + "/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: AuthoritiesPath + "/" + framework.GenericNameRegex("ENTITYORATTRIBUTE") + "/" + framework.GenericNameRegex("ATTRIBUTE") + "/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: AuthoritiesPath + "/" + framework.GenericNameRegex("ENTITYORATTRIBUTE") + "/" + framework.GenericNameRegex("ATTRIBUTE") + "/" + framework.GenericNameRegex("DATA_ACCESS") + "/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleRead,
			},
		},
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) { //Should research on how to implement this function
	out, err := req.Storage.Get(ctx, req.ClientToken+"/"+req.Path)

	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *backend) authSetup(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authorityAttrs := data.Get("authorityAttributes").([]string)
	commonAttrs := data.Get("commonAttributes").([]string)
	authority := data.Get("authorityName").(string)

	if len(authorityAttrs) == 0 && len(commonAttrs) == 0 {
		return logical.ErrorResponse("Wrong number of initialization attributes"), nil
	}

	//Turn every Attribute to uppercase in order to avoid conflicts in the future
	for i := range authorityAttrs {
		authorityAttrs[i] = strings.ToUpper(authorityAttrs[i])
	}
	for i := range commonAttrs {
		commonAttrs[i] = strings.ToUpper(commonAttrs[i])
	}

	//Checks for Reserved Attributes by the System
	isSystemAttributeList, isSystemAttribute, err := b.attributeNotASystemAttribute(ctx, authorityAttrs, commonAttrs)
	if err != nil {
		return nil, err
	}
	if isSystemAttribute {
		return logical.ErrorResponse(fmt.Sprintf("These Attributes are System Attributes that can not be used by an entity other than the System entity: %s", isSystemAttributeList)), nil
	}

	mergedAttrs := make([]*mergedAttributes, 0)
	var existanceMessage string

	if len(commonAttrs) > 0 {
		attrsAlreadyExist, message, err := b.mergeCommonAndAuthorityAttributes(ctx, &mergedAttrs, CommonAttributes, commonAttrs, true)
		if err != nil {
			return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
		}
		if attrsAlreadyExist {
			existanceMessage += ("Common Attributes: " + message)
		}
	}
	if len(authorityAttrs) > 0 {
		attrsAlreadyExist, message, err := b.mergeCommonAndAuthorityAttributes(ctx, &mergedAttrs, authority, authorityAttrs, true)
		if err != nil {
			return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
		}
		if attrsAlreadyExist {
			if existanceMessage != "" {
				existanceMessage += " - "
			}
			existanceMessage += ("Authority Attributes: " + message)
		}
	}
	if existanceMessage != "" {
		existanceMessage = fmt.Sprintf("Attribute(s) already exist: " + existanceMessage)
		return logical.ErrorResponse(existanceMessage), nil
	}

	var publishedDataResponseCommon []*keysDataAsResponse
	var publishedDataResponseAuthority []*keysDataAsResponse

	ecElement := b.getABEElement()

	for _, value := range mergedAttrs {
		attribute := strings.ToUpper(value.attribute)
		alpha_i, y_i := ecElement.Pairing().NewZr(), ecElement.Pairing().NewZr()
		alpha_i.Rand()
		y_i.Rand()

		e_gg_alpha_i := ecElement.Pairing().NewGT().Pair(ecElement, ecElement).ThenPowZn(alpha_i)
		g_y_i := ecElement.Pairing().NewG1().Set(ecElement).ThenPowZn(y_i)

		publishedData := &keysData{
			Attribute: attribute,
			Alphai:    e_gg_alpha_i.Bytes(),
			Yi:        g_y_i.Bytes(),
		}

		publishedDataResponseConstructor := &keysDataAsResponse{
			Attribute: attribute,
			Alphai:    e_gg_alpha_i.String(),
			Yi:        g_y_i.String(),
		}

		//We need some feedback for the invoker - thus, we construct a custom response
		if value.isCommon {
			publishedDataResponseCommon = append(publishedDataResponseCommon, publishedDataResponseConstructor)
		} else {
			publishedDataResponseAuthority = append(publishedDataResponseAuthority, publishedDataResponseConstructor)
		}

		privateData := &keysData{
			Attribute: attribute,
			Alphai:    alpha_i.Bytes(),
			Yi:        y_i.Bytes(),
		}

		var constructedPath string

		if value.isCommon {
			constructedPath = b.constructPath([]string{AuthoritiesPath, CommonAttributes})
		} else {
			constructedPath = b.constructPath([]string{AuthoritiesPath, authority})
		}

		if err := b.dataKeyStore(ctx, publishedData, privateData, constructedPath, attribute); err != nil {
			return nil, errwrap.Wrapf("failed to import the new attributes: {{err}}", err)
		}
	}

	// Return the public keys only if there were no problems up till this point.
	return &logical.Response{
		Data: map[string]interface{}{
			"generated_data": map[string]interface{}{
				"public_segments": map[string]interface{}{
					"common_attributes":    publishedDataResponseCommon,
					"authority_attributes": publishedDataResponseAuthority,
				},
			},
		},
	}, nil
}
