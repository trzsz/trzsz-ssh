/*
MIT License

# Copyright (c) 2022-2025 wencaiwulue

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package krb5

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

type Krb5ClientState int

const (
	ContextFlagREADY = 128
	/* initiator states */
	InitiatorStart Krb5ClientState = iota
	InitiatorRestart
	InitiatorWaitForMutal
	InitiatorReady
)

func NewKrb5InitiatorClientWithPassword(username, password, krb5Conf string) (kcl Krb5InitiatorClient, err error) {
	c, err := config.Load(krb5Conf)
	if err != nil {
		return
	}

	defaultRealm := c.LibDefaults.DefaultRealm

	cl := client.NewWithPassword(username, defaultRealm, password, c)
	err = cl.Login()
	if err != nil {
		return
	}
	err = cl.AffirmLogin()
	if err != nil {
		return
	}

	return Krb5InitiatorClient{
		client: cl,
		state:  InitiatorStart,
	}, nil
}

func NewKrb5InitiatorClientWithKeytab(username string, krb5Conf, keytabConf string) (kcl Krb5InitiatorClient, err error) {
	c, err := config.Load(krb5Conf)
	if err != nil {
		return
	}

	// Init keytab from conf
	cache, err := keytab.Load(keytabConf)
	if err != nil {
		return kcl, fmt.Errorf("unmarshal keytabConf failed: %w", err)
	}

	defaultRealm := c.LibDefaults.DefaultRealm

	cl := client.NewWithKeytab(username, defaultRealm, cache, c)
	err = cl.Login()
	if err != nil {
		return
	}
	err = cl.AffirmLogin()
	if err != nil {
		return
	}

	return Krb5InitiatorClient{
		client: cl,
		state:  InitiatorStart,
	}, nil
}

func NewKrb5InitiatorClientWithCache(krb5Conf, cacheFile string) (kcl Krb5InitiatorClient, err error) {
	c, err := config.Load(krb5Conf)
	if err != nil {
		return
	}

	// Init krb5 client and login
	cache, err := credentials.LoadCCache(cacheFile)
	// https://stackoverflow.com/questions/58653482/what-is-the-default-kerberos-credential-cache-on-osx
	if err != nil {
		return
	}
	cl, err := client.NewFromCCache(cache, c)
	if err != nil {
		return
	}
	err = cl.Login()
	if err != nil {
		return
	}
	err = cl.AffirmLogin()
	if err != nil {
		return
	}

	return Krb5InitiatorClient{
		client: cl,
		state:  InitiatorStart,
	}, nil
}

type Krb5InitiatorClient struct {
	state  Krb5ClientState
	client *client.Client
	subkey types.EncryptionKey
}

// Create new authenticator checksum for kerberos MechToken
func (k *Krb5InitiatorClient) newAuthenticatorChksum(flags []int) []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			x := make([]byte, 28-len(a))
			a = append(a, x...)
		}
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}

func (k *Krb5InitiatorClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error) {
	GSSAPIFlags := []int{
		ContextFlagREADY,
		gssapi.ContextFlagInteg,
		gssapi.ContextFlagMutual,
	}
	if isGSSDelegCreds {
		GSSAPIFlags = append(GSSAPIFlags, gssapi.ContextFlagDeleg)
	}
	APOptions := []int{flags.APOptionMutualRequired}

	switch k.state {
	case InitiatorStart, InitiatorRestart:
		newTarget := strings.ReplaceAll(target, "@", "/")

		tkt, sessionKey, err := k.client.GetServiceTicket(newTarget)
		if err != nil {
			return []byte{}, false, err
		}

		krb5Token, err := spnego.NewKRB5TokenAPREQ(k.client, tkt, sessionKey, GSSAPIFlags, APOptions)
		if err != nil {
			return nil, false, fmt.Errorf("error generating new kerberos 5 token: %w", err)
		}
		creds := k.client.Credentials
		auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
		if err != nil {
			return nil, false, fmt.Errorf("error generating new authenticator: %w", err)
		}
		auth.Cksum = types.Checksum{
			CksumType: chksumtype.GSSAPI,
			Checksum:  k.newAuthenticatorChksum(GSSAPIFlags),
		}
		etype, _ := crypto.GetEtype(sessionKey.KeyType)
		if err := auth.GenerateSeqNumberAndSubKey(sessionKey.KeyType, etype.GetKeyByteSize()); err != nil {
			return nil, false, err
		}
		k.subkey = auth.SubKey

		APReq, err := messages.NewAPReq(
			tkt,
			sessionKey,
			auth,
		)
		if err != nil {
			return nil, false, fmt.Errorf("error generating NewAPReq: %w", err)
		}
		for _, o := range APOptions {
			types.SetFlag(&APReq.APOptions, o)
		}
		krb5Token.APReq = APReq

		outToken, err := krb5Token.Marshal()
		if err != nil {
			fmt.Println(err)
			return []byte{}, false, err
		}
		k.state = InitiatorWaitForMutal
		return outToken, true, nil
	case InitiatorWaitForMutal:
		var krb5Token spnego.KRB5Token
		if err := krb5Token.Unmarshal(token); err != nil {
			err := fmt.Errorf("unmarshal APRep token failed: %w", err)
			return []byte{}, false, err
		}
		//var enc messages.EncAPRepPart
		//err2 := enc.Unmarshal(krb5Token.APRep.EncPart.Cipher)
		//fmt.Printf("err2: %#v, enc: %#v\n", err2, enc)

		k.state = InitiatorReady
		return []byte{}, false, nil
	case InitiatorReady:
		return nil, false, fmt.Errorf("called one time too many, client has already been %d", k.state)
	default:
		return nil, false, fmt.Errorf("invalid state %d", k.state)
	}
}

func (k *Krb5InitiatorClient) GetMIC(micFiled []byte) ([]byte, error) {
	micToken, err := gssapi.NewInitiatorMICToken(micFiled, k.subkey)
	if err != nil {
		return nil, err
	}
	token, err := micToken.Marshal()
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (k *Krb5InitiatorClient) DeleteSecContext() error {
	k.client.Destroy()
	return nil
}
