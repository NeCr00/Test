package abe

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"math/big"

	"github.com/Nik-U/pbc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSysDecrypt(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "sysdecrypt/" + framework.GenericNameRegex("entity_id") + "/" + framework.GenericNameRegex("subject"),

			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: "[Required] Name of the authority",
				},
				"subject": {
					Type:        framework.TypeString,
					Description: "[Required] The policy to use for system decryption",
				},
				"sub_policy": {
					Type:        framework.TypeString,
					Description: "[Required] The policy to use for system decryption",
				},
				"cryptogram": {
					Type:        framework.TypeString,
					Description: "[Required] Receives the attributes with which an Authority can create their keys",
					Required:    true,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.sysDecrypt,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.sysDecrypt,
					Summary:  "Store a secret at the specified location.",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,
					Summary:  "Retrieve the secret at the specified location.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback:    b.handleList,
					Summary:     "List secret entries at the specified location.",
					Description: "Folders are suffixed with /. The input must be a folder; list on a file will not return a value. The values themselves are not accessible via this command.",
				},
			},
		},
	}
}

func (b *backend) sysDecrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Invoked: System Decryption")

	GID := data.Get("entity_id").(string)
	subject := data.Get("subject").(string)
	sub_policy_str := data.Get("sub_policy").(string)

	//First, we should check if the attribute is a SYSTEM Attribute or a common/authority attribute; If it is a SYSTEM Attribute, then we need to aggregate the ABE Keys of an authority, else of a user.
	//If the policy has both (a SYSTEM Attribute AND a COMMON/AUTHORITY Attribute), then we must interrupt the process.
	sub_policy := createPolicy(sub_policy_str)
	policyAttrs := sub_policy.getAttributeList()

	dataFromEncryption := data.Get("cryptogram").(string)
	b64DecodedDataFromEncryption, base64ErrDataFromEncryption := b64.StdEncoding.DecodeString(dataFromEncryption)
	if base64ErrDataFromEncryption != nil {
		return nil, base64ErrDataFromEncryption
	}
	var cts cryptogram
	err := json.Unmarshal(b64DecodedDataFromEncryption, &cts)
	if err != nil {
		return nil, err
	}

	systemAttributeEntries, err := b.getEntries(ctx, []string{AuthoritiesPath, SystemAttributes})
	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}
	_, nonExistentAttrsExist := b.checkNonExistentAttr(systemAttributeEntries, policyAttrs)
	// If nonExistentAttrsExist == true, it means that the given attributes are NOT SYSTEM Attributes or that the given attributes include both SYSTEM AND COMMON/AUTHORITY Attributes
	// We will continue as if the given attributes are only COMMON/AUTHORITY Attributes and try to (partially) decrypt the message with both the COMMON AND the AUTHORITY Attributes
	// BUT, if nonExistentAttrsExist == false, that means that the given attributes are ONLY SYSTEM ATTRIBUTES!
	
	ecElement := b.getABEElement()

	gidData, _ := b.loadGIDData(ctx, req, GID)

	gidMapper := b.createHashMapper(ecElement)
	hashedGIDInEC := gidMapper(subject)

	//Merge all attributes as one
	mergedAttrs := make(map[string][]byte)
	mergedAttrsList := []string{}

	for _, attribute := range policyAttrs {
		if !nonExistentAttrsExist { // No need to check for attributes
			if sliceContains(gidData.SYSTEM_ATTRIBUTES, attribute) {
				constructedSystemAttribute, err := b.constructSystemAttribute(ctx, req, attribute, hashedGIDInEC)
				if err != nil {
					return nil, err
				}
				mergedAttrs[attribute] = constructedSystemAttribute
				mergedAttrsList = append(mergedAttrsList, attribute)
				continue
			}

			if gidData.COMMON_ATTRIBUTES[attribute] != nil {
				mergedAttrs[attribute] = gidData.COMMON_ATTRIBUTES[attribute]
				mergedAttrsList = append(mergedAttrsList, attribute)
				continue
			}
		}

		for _, authorities := range gidData.AUTHORITY_ATTRIBUTES {
			if authorities[attribute] != nil {
				mergedAttrs[attribute] = authorities[attribute]
				mergedAttrsList = append(mergedAttrsList, attribute)
				break
			}
		}
	}


	policy := createPolicy(cts.PolicyStr)
	coeff_list := make(map[string]*pbc.Element)

	policy.getCoefficients(ecElement, coeff_list)
	policySatisfied, pruned := sub_policy.prune(mergedAttrsList)

	if !policySatisfied {
		return logical.ErrorResponse(`The given Policy does not satisfy the available attributes`), nil
	}

	EggS := ecElement.Pairing().NewGT()

	for _, attribute := range pruned {
		attributeCoeff, attributeCoeffIsOk := new(big.Int).SetString(coeff_list[attribute].String(), 10)
		if !attributeCoeffIsOk {
			return logical.ErrorResponse(`The System does not utilize any System attributes`), nil
		}

		C1Element := ecElement.Pairing().NewGT().SetBytes(cts.C1[attribute])
		C2Element := ecElement.Pairing().NewG1().SetBytes(cts.C2[attribute])
		C3Element := ecElement.Pairing().NewG1().SetBytes(cts.C3[attribute])

		fieldNumBase := ecElement.Pairing().NewGT()
		fieldNumEl := ecElement.Pairing().NewGT().Pair(hashedGIDInEC, C3Element)
		fieldNumBase.Set(C1Element).ThenMul(fieldNumEl)

		gidEC := ecElement.Pairing().NewG1().SetBytes(mergedAttrs[attribute])

		fieldDemBase := ecElement.Pairing().NewGT().Pair(gidEC, C2Element)

		div := ecElement.Pairing().NewGT().Set(fieldNumBase).ThenDiv(fieldDemBase)

		EggS = ecElement.Pairing().NewGT().Set(div).ThenPowBig(attributeCoeff)
	}

	cts.SysDecrypted = EggS.Bytes()

	exported, err := json.Marshal(cts)
	if err != nil {
		return nil, err
	}

	b64Encoded := b64.StdEncoding.EncodeToString([]byte(exported))

	return &logical.Response{
		Data: map[string]interface{}{
			"b64_enc_data_sysdec": b64Encoded,
		},
	}, nil
}

func (b *backend) constructSystemAttribute(ctx context.Context, req *logical.Request, systemAttribute string, hashedGIDInEC *pbc.Element) ([]byte, error) {
	alphai, yi, err := b.getKeyData(ctx, req, systemAttribute, "", false, true, true)
	if err != nil {
		return nil, errwrap.Wrapf("failed: {{err}}", err)
	}
	ecElement := b.getABEElement()

	fieldBase := ecElement.Pairing().NewG1()
	fieldh := ecElement.Pairing().NewG1().Set(hashedGIDInEC).ThenPowZn(yi)
	fieldR := ecElement.Pairing().NewG1().Set(ecElement).ThenPowZn(alphai)

	systemAttributeAsBytes := fieldBase.Set(fieldR).ThenMul(fieldh).Bytes()

	return systemAttributeAsBytes, nil
}
