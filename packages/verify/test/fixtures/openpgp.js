/*
Copyright 2021 Yarmo Mackenbach

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import HKP from '@openpgp/hkp-client'
import WKD from '@openpgp/wkd-client'

export const publicKeyFingerprint = '3637202523e7c1309ab79e99ef2dc5827b445f4b'
export const publicKeyEmail = 'test@doip.rocks'
export const publicKeyId = 'ef2dc5827b445f4b'

// Public-only test key snapshot retrieved on 2026-08-29 from
// https://keys.openpgp.org/vks/v1/by-fingerprint/3637202523E7C1309AB79E99EF2DC5827B445F4B.
// The fixture contains no private or secret key material.
export const publicKeyArmored = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBF+036UBDACoxWRdp7rBAFB2l/+dxX0XA50NJC92EEacB5L0TnC0lP/MsNHv
fAv/A9vgTwrPudvcHdE/urAjQswfIU3LpFxbBOWNYWOv6ssrzBH4vVGMyxfu2GGu
b2mxjWj0eWXnWXnzkO5fscX2y0HqNjBZjDSkYohHZJTbz91NnxK3a8+Erpk+sgEH
hQH1h75SfaW6GZucuhenxgjwEiGz84UEVS0AEWD9yNgfWCsK/6HuIRnv5Jv5V9z9
bx9Ik7QNGBks3tpNmdbeaaadkHYZpF3Fm8mCoIt2+Xx9OvyuLssZnVkuQdj8C2/z
E45If4+pHRnRcCWXpDrHUWoJaeyGuTq5triePI6h/4lgr/m/du0O/lhOrr6MUhAe
7xc0B+X+bTF/balZmmlbk5bnDoZMzdH8caui5XrkuRif/I0nYPRnc9zrqWJDDO/p
nltpMPrUMTjoiXZ8DbJ4WMK7QPdsbG8Tz/Vl3wigEmwPLfEGifLpec5RXrti5Zd9
FiSOIOetP8p8MSMAEQEAAbRBWWFybW8gTWFja2VuYmFjaCAobWF0ZXJpYWwgZm9y
IHRlc3QgZnJhbWV3b3JrcykgPHRlc3RAZG9pcC5yb2Nrcz6JAhAEEwEKAHoCGwMF
CwkIBwIGFQoJCAsCBBYCAwECHgECF4AZGGh0dHBzOi8va2V5cy5vcGVucGdwLm9y
ZxYhBDY3ICUj58Ewmreeme8txYJ7RF9LBQJhhrogJxSAAAAAABAADnByb29mQGFy
aWFkbmUuaWRkbnM6ZG9pcC5yb2NrcwAKCRDvLcWCe0RfS6LbC/9mdVWS8qiZcM0b
tcekjGXXDKWggdeYVxHMcSCypvuI7Rha8vRKGnfvtY6Wy36YsW40u6vdaw4UIFGy
6Y/8RhaT6eN0EZ8t4VQv8HXyHeWqqQSfBpyU77spcxv27Wo24OhrI9ErmxXHAjqk
Hp46lA1nJjGRkzQs09KFRPd4nL4NInV1me1G8szxzowlLbRIZ3bNqhnPTeVOa779
j8aupCr0W08W0f6FxcDxGgQBT1ytLcc1nQdhgkXppTlso+JvOr2sjff4suSXY3gC
GcTGwRX15q3YDTv36KtlBlus2f4oGk1mjqZAESklrTHCfifZW102mkKBzZ+Y0EwN
B9ODBwJNrsbqBqXMs1wQkP81O3ihONwhz5XuykJF3G0VeoOy1zSL4ghZQ4/XkWyp
fCRSXrr7SZxIu7I8jfQrxc0k9XhpPI/gdlgRqoEG2lMyqFaWzyoI9dyoVwji78rg
8t7V+BjcvC8fJHgXUZxljqi2ZfcismJE6Hyn6qsdlNF9SKWOIIg=
=Csr+
-----END PGP PUBLIC KEY BLOCK-----`

export async function installOpenPgpFixtureHkp () {
  const originalHkpLookup = HKP.prototype.lookup
  const originalWkdLookup = WKD.prototype.lookup
  const calls = []
  const fixtureQueries = new Set([
    publicKeyFingerprint,
    publicKeyEmail,
    publicKeyId
  ])

  HKP.prototype.lookup = async function ({ query }) {
    const url = `${this._baseUrl}/pks/lookup?op=get&options=mr&search=${encodeURIComponent(query)}`
    calls.push({ protocol: 'hkp', query, baseUrl: this._baseUrl, url })
    if (
      this._baseUrl !== 'https://keys.openpgp.org' ||
      !fixtureQueries.has(query.toLowerCase())
    ) {
      throw new Error('OpenPGP fixture key not found')
    }
    return publicKeyArmored
  }

  WKD.prototype.lookup = async function ({ email }) {
    calls.push({ protocol: 'wkd', query: email })
    throw new Error('OpenPGP fixture has no WKD record')
  }

  return {
    calls,
    restore () {
      HKP.prototype.lookup = originalHkpLookup
      WKD.prototype.lookup = originalWkdLookup
    }
  }
}
