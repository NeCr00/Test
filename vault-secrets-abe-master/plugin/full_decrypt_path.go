package abe

import (
	"context"
	"crypto/aes"
	cbc "crypto/cipher"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"math/big"
	"strings"

	"github.com/Nik-U/pbc"
	"github.com/go-errors/errors"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathFullDecrypt(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "decrypt" + "/" + framework.GenericNameRegex("entity_id"),

			Fields: map[string]*framework.FieldSchema{
				"entity_id": {
					Type:        framework.TypeString,
					Description: "[Required] Name of the subject",
				},
				"cryptogram": {
					Type:        framework.TypeString,
					Description: "The cryptogram",
					Required:    true,
				},
				"sub_policy": {
					Type:        framework.TypeString,
					Description: "[Required] The policy to use for system decryption",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.fullDecrypt,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.fullDecrypt,
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

func (b *backend) fullDecrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Invoked: Final Decryption")

	GID := data.Get("entity_id").(string)
	sub_policy_str := data.Get("sub_policy").(string)

	sub_policy := createPolicy(sub_policy_str)

	encryptedMessage := data.Get("cryptogram").(string)

	b64DecodedEncMsg, b64EncMsgErr := b64.StdEncoding.DecodeString(encryptedMessage)
	if b64EncMsgErr != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", b64EncMsgErr)
	}
	var cts cryptogram
	err := json.Unmarshal(b64DecodedEncMsg, &cts)
	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	ecElement := b.getABEElement()

	policyAttrs := sub_policy.getAttributeList()
	GIDData, _ := b.loadGIDData(ctx, req, GID)
	// Merge all the available attributes, together
	mergedAttrs := make(map[string][]byte)
	mergedAttrsList := []string{} // We need to construct and populate this list in order to check if our attributes define the given policy

	for _, attribute := range policyAttrs {
		if GIDData.COMMON_ATTRIBUTES[attribute] != nil {
			mergedAttrs[attribute] = GIDData.COMMON_ATTRIBUTES[attribute]
			mergedAttrsList = append(mergedAttrsList, attribute)
			continue
		}

		for authority, authAttributes := range GIDData.AUTHORITY_ATTRIBUTES {
			authority = strings.ToUpper(authority)
			// Separate the Authority from the Attribute
			// e.g. Attribute[Authority0] => Authority0, Attribute
			authorityAttribute, trimmedAttribute, err := b.separateAuthorityFromAttribute(attribute)

			if (err != nil) {
				return nil, errwrap.Wrapf("Internal error: {{err}}", err)
			}

			if (authority == authorityAttribute) {
				if authAttributes[trimmedAttribute] != nil {
					mergedAttrs[attribute] = authAttributes[trimmedAttribute]
					mergedAttrsList = append(mergedAttrsList, attribute)
					break
				}
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

	gidMapper := b.createHashMapper(ecElement)
	hashedGIDInEC := gidMapper(GID)

	for _, attribute := range pruned {
		attributeCoeff, attributeCoeffIsOk := new(big.Int).SetString(coeff_list[attribute].String(), 10) // If an attribute is not known, returns an error (policySatisfied should be used instead) - Should investigate
		if !attributeCoeffIsOk {
			return nil, errwrap.Wrapf("error with attribute's coefficient", errors.New("Coefficient error"))
		}

		C1Element := ecElement.Pairing().NewGT().SetBytes(cts.C1[attribute])
		C2Element := ecElement.Pairing().NewG1().SetBytes(cts.C2[attribute])
		C3Element := ecElement.Pairing().NewG1().SetBytes(cts.C3[attribute])

		SKElement := ecElement.Pairing().NewG1().SetBytes(mergedAttrs[attribute])

		fieldNumBase := ecElement.Pairing().NewGT()
		fieldNumEl := ecElement.Pairing().NewGT()
		fieldNumEl.Pair(hashedGIDInEC, C3Element)
		fieldNumBase.Set(C1Element).ThenMul(fieldNumEl)

		fieldDemBase := ecElement.Pairing().NewGT()
		fieldDemBase.Pair(SKElement, C2Element)

		div := ecElement.Pairing().NewGT()
		div.Set(fieldNumBase).ThenDiv(fieldDemBase)
		div.PowBig(div, attributeCoeff)

		EggS.Mul(EggS, div)
	}

	if len(cts.SysDecrypted) > 0 {
		sys_decrypted := ecElement.Pairing().NewGT().SetBytes(cts.SysDecrypted)
		EggS.ThenMul(sys_decrypted)
	}

	C0Element := ecElement.Pairing().NewGT().SetBytes(cts.C0)
	decrypted := ecElement.Pairing().NewGT().Set(C0Element).ThenDiv(EggS)

	// The `decrypted` element is the EC element that is related with our secret key
	// We will recreate the secret key
	randomKey := sha256.Sum256([]byte(decrypted.String()))
	cipher, err := aes.NewCipher(randomKey[:])

	if err != nil {
		return logical.ErrorResponse(`Decryption error (Error Code: 1)`), nil
	}

	secretMsgPadded := make([]byte, len(cts.EncryptedMessage))
	decrypter := cbc.NewCBCDecrypter(cipher, cts.CipherIV)
	decrypter.CryptBlocks(secretMsgPadded, cts.EncryptedMessage)

	paddingLength := int(secretMsgPadded[len(secretMsgPadded)-1])

	if (len(secretMsgPadded) - paddingLength) < 0 {
		return logical.ErrorResponse(`Decryption error (Error Code: 2)`), nil
	}

	msgBytes := secretMsgPadded[0:(len(secretMsgPadded) - paddingLength)]

	return &logical.Response{
		Data: map[string]interface{}{
			"decrypted_data": string(msgBytes),
		},
	}, nil
}
