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
import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

import { openpgp, Profile } from '../src/index.js'
import {
  installOpenPgpFixtureHkp,
  publicKeyArmored,
  publicKeyEmail as pubKeyEmail,
  publicKeyFingerprint as pubKeyFingerprint
} from './fixtures/openpgp.js'

const pubKeyPlaintext = publicKeyArmored

const pubKeyWithOtherNotations = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEX9Mt6xYJKwYBBAHaRw8BAQdAch8jfp+8KHH5cy/t45GjPvl6dkEv2soIy9fo
Oe9DbP20EVlhcm1vJ3MgRXZpbCBUd2luiNsEExYIAIMCGwMFCwkIBwIGFQoJCAsC
BBYCAwECHgECF4AWIQTeePcduHH8EU2iM3aw5zJVrULhnwUCX9MuHBkUgAAAAAAN
AANldmlsQHlhcm1vLmV1eWVzMBSAAAAAABIAFXByb29mQG1ldGFjb2RlLmJpemRu
czp5YXJtby5ldT90eXBlPVRYVAAKCRCw5zJVrULhn4DtAQCVkyI8UxUbkxspXkWB
qUL+3uqCl9gTbNImhv/OxxJdEAEAqf8SJ9FSeAwgWhPHOidR1m+J6/qVdAJdp0HJ
Yn6RMQ8=
=Oo3X
-----END PGP PUBLIC KEY BLOCK-----`

const pubKeyWithRevokedUID = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EYLitOQEEAMUKTmcNdy46gjcuz0oRsUyq0BythQGSrcLvLGAyZIzKR8NZXZSA
UAIHuQkWVwqJjYPSRrTp8op8LZIHmhP3W3TgG5WHSOhcPeIYe1JTB0b7XceIIJ3p
/FfT9xFhWgeAVfAHQUcK/p4+mhvQRfDDf5Jbh/i37cY3iF5huNyXZYY9ABEBAAG0
F1lhcm1vJ3MgU3VwZXIgRXZpbCBUd2luiLYEMAEKACAWIQQKQsh7jbmy9ycMulRn
U1zbmU0aJAUCYLiu7QIdIAAKCRBnU1zbmU0aJGr1A/9VMS9xexufTLHenWCquAsL
cnzciPTvYy7h+OYAkXQEmzOcUcy9a71w5/ElEWubqySZuUUeB7Y8UHjowXOVF5Ty
BRyiSIiHmwXspjCtc5q97fWuuAiVdyHMWMSThuY+y+D4pxcfeO1lu5zND3vUUGjy
CJWtYDGTVQ41nLU4WM8NTIjOBBMBCgA4FiEECkLIe425svcnDLpUZ1Nc25lNGiQF
AmC4rgsCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQZ1Nc25lNGiRSWQQA
wUM2h4uSyaOUT+qrL0/UTUqD3Mp0Ajg/n81S9GBcKhSxIK2RMIBCJbSw7nzdj2Ev
gCwd3DuI0Mqxiu29LtNN+bsEWZ6RbsrxgkgzQy2wyGf6DHS9W7GcliyIWnHSh/Jc
dTREbVl0aFXOTLh7JAoED31pf3uv372YJyQfjvqDlLC0EVlhcm1vJ3MgRXZpbCBU
d2luiM4EEwEKADgWIQQKQsh7jbmy9ycMulRnU1zbmU0aJAUCYLitOQIbAwULCQgH
AgYVCgkICwIEFgIDAQIeAQIXgAAKCRBnU1zbmU0aJMnBBACydud5WYsmD/Tvjxf6
MiOl/s0zMLZdk6ofEutMvcmN8PGri1hMqr2R2lTN+cH4HALWbixuDr1sYjOwt2eb
6e8ubOhEm30JGJE8eiM9jHRUgeRQZhPnj/ky/fZUcMY5fZPeti3q7kzBMRscuSbW
9v8AArWmybhfudyjf7Lhb5R3UriNBGC4rTkBBADVCDORKNEyjOQutpxvR8y1nBdy
VfCKQ0mUiV9/Z1PvhW3s98RyjDZcYURhgPXUD04EKtgH6ar6Q4pZovZmRL6Jz+82
4OWmFk4dzje/MLYIeV6hwq7IIeKzUy4NCl/aX7y0Hru/8fiBNPtu+ycIZSgNxDQQ
NwHRpZvplgOJ/cuCYwARAQABiLYEGAEKACAWIQQKQsh7jbmy9ycMulRnU1zbmU0a
JAUCYLitOQIbDAAKCRBnU1zbmU0aJIaRA/9Zz0u7zkwBVSTUcXLd3NwCmkzHnuQo
kRIDpwkXa08iG0GXBV/ZEPGNzPbaMCZVqqiVlf9+BxX1rnG6ENseGKPn8Q+RIKUb
Q+AZdYCbM0hdBjP4xdKZcpqak8ksb+aQFXjGacDL/XN4VrP+tBGxkqIqreoDcgIb
7t1hISc09hWrGQ==
=tVW7
-----END PGP PUBLIC KEY BLOCK-----`

let openPgpFixture

function useOpenPgpFixtureHkp () {
  before(async () => {
    openPgpFixture = await installOpenPgpFixtureHkp()
  })

  after(() => {
    openPgpFixture.restore()
  })
}

describe('openpgp.fetch', () => {
  useOpenPgpFixtureHkp()

  it('should be a function (1 argument)', () => {
    expect(openpgp.fetch).to.be.a('function')
    expect(openpgp.fetch).to.have.length(1)
  })
  it('should return a Key object when provided a valid fingerprint', async () => {
    const profile = await openpgp.fetch(pubKeyFingerprint)
    expect(profile).to.be.instanceOf(Profile)
    expect(profile.publicKey.fetch.method).to.be.equal('hkp')
    expect(profile.publicKey.fetch.query).to.be.equal(pubKeyFingerprint)
    expect(openPgpFixture.calls.at(-1)).to.include({
      protocol: 'hkp',
      query: pubKeyFingerprint,
      baseUrl: 'https://keys.openpgp.org'
    })
  }).timeout('12s')
  it('should return a Key object when provided a valid email address', async () => {
    const profile = await openpgp.fetch(pubKeyEmail)
    expect(profile).to.be.instanceOf(Profile)
    expect(profile.publicKey.fetch.method).to.be.equal('hkp')
    expect(profile.publicKey.fetch.query).to.be.equal(pubKeyEmail)
    expect(openPgpFixture.calls.slice(-2).map(({ protocol }) => protocol)).to.deep.equal([
      'wkd',
      'hkp'
    ])
  }).timeout('12s')
  it('should reject when provided an invalid email address', () => {
    return expect(
      openpgp.fetch('invalid@doip.rocks')
    ).to.eventually.be.rejectedWith('Key does not exist or could not be fetched')
  }).timeout('12s')
})

describe('openpgp.fetchURI', () => {
  useOpenPgpFixtureHkp()

  it('should be a function (1 argument)', () => {
    expect(openpgp.fetchURI).to.be.a('function')
    expect(openpgp.fetchURI).to.have.length(1)
  })
  it('should return a Key object when provided a hkp: uri', async () => {
    const profile = await openpgp.fetchURI(`hkp:${pubKeyFingerprint}`)
    expect(profile).to.be.instanceOf(Profile)
    expect(profile.publicKey.fetch.method).to.be.equal('hkp')
    expect(profile.publicKey.fetch.query).to.be.equal(pubKeyFingerprint)
  }).timeout('12s')
  it('should reject when provided an invalid uri', () => {
    return expect(
      openpgp.fetchURI(`inv:${pubKeyFingerprint}`)
    ).to.eventually.be.rejectedWith('Invalid URI protocol')
  }).timeout('12s')
})

describe('openpgp.fetchHKP', () => {
  useOpenPgpFixtureHkp()

  it('should be a function (1 required argument, 1 optional argument)', () => {
    expect(openpgp.fetchHKP).to.be.a('function')
    expect(openpgp.fetchHKP).to.have.length(1)
  })
  it('should return a Key object when provided a valid fingerprint', async () => {
    const profile = await openpgp.fetchHKP(pubKeyFingerprint)
    expect(profile).to.be.instanceOf(Profile)
    expect(profile.publicKey.fetch.method).to.be.equal('hkp')
    expect(profile.publicKey.fetch.query).to.be.equal(pubKeyFingerprint)
  }).timeout('12s')
  it('should return a Key object when provided a valid email address', async () => {
    const profile = await openpgp.fetchHKP(pubKeyEmail)
    expect(profile).to.be.instanceOf(Profile)
    expect(profile.publicKey.fetch.method).to.be.equal('hkp')
    expect(profile.publicKey.fetch.query).to.be.equal(pubKeyEmail)
  }).timeout('12s')
  it('should reject when provided an invalid fingerprint', async () => {
    return expect(
      openpgp.fetchHKP('4637202523e7c1309ab79e99ef2dc5827b445f4b')
    ).to.eventually.be.rejectedWith(
      'Key does not exist or could not be fetched'
    )
  }).timeout('12s')
  it('should reject when provided an invalid email address', async () => {
    return expect(
      openpgp.fetchHKP('invalid@doip.rocks')
    ).to.eventually.be.rejectedWith(
      'Key does not exist or could not be fetched'
    )
  }).timeout('12s')
})

describe('openpgp.fetchPlaintext', () => {
  it('should be a function (1 argument)', () => {
    expect(openpgp.fetchPlaintext).to.be.a('function')
    expect(openpgp.fetchPlaintext).to.have.length(1)
  })
  it('should return a Key object', async () => {
    expect(await openpgp.fetchPlaintext(pubKeyPlaintext)).to.be.instanceOf(
      Profile
    )
  }).timeout('12s')
})

describe('openpgp.parsePublicKey', () => {
  it('should be a function (1 argument)', () => {
    expect(openpgp.parsePublicKey).to.be.a('function')
    expect(openpgp.parsePublicKey).to.have.length(1)
  })
  it('should return an object with specific openpgp', async () => {
    const pubKey = await openpgp.fetchPlaintext(pubKeyPlaintext)
    const profile = await openpgp.parsePublicKey(pubKey.publicKey.key)
    expect(profile).to.be.instanceOf(Profile)
  })
  it('should ignore non-proof notations', async () => {
    const pubKey = await openpgp.fetchPlaintext(pubKeyWithOtherNotations)
    const profile = await openpgp.parsePublicKey(pubKey.publicKey.key)
    expect(profile.personas).to.be.lengthOf(1)
    expect(profile.personas[0].claims).to.be.lengthOf(1)
    expect(profile.personas[0].claims[0].uri).to.be.equal('dns:yarmo.eu?type=TXT')
  })
  it('should properly handle revoked UIDs', async () => {
    const pubKey = await openpgp.fetchPlaintext(pubKeyWithRevokedUID)
    const profile = await openpgp.parsePublicKey(pubKey.publicKey.key)
    expect(profile.personas).to.be.lengthOf(2)
    expect(profile.personas[0].isRevoked).to.be.true
    expect(profile.personas[1].isRevoked).to.be.false
  })
})
