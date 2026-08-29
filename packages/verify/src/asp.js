/*
Copyright 2023 Yarmo Mackenbach

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
import axios from 'axios'
import { decodeProtectedHeader, importJWK, compactVerify, calculateJwkThumbprint } from 'jose'
import { base32, base64url } from 'rfc4648'
import { Claim } from './claim.js'
import { Persona } from './persona.js'
import { Profile } from './profile.js'
import { ProfileType, PublicKeyEncoding, PublicKeyFetchMethod, PublicKeyType } from './enums.js'

const SupportedCryptoAlg = ['EdDSA', 'ES256', 'ES256K', 'ES384', 'ES512']

/**
 * Functions related to Ariadne Signature Profiles
 * @module asp
 */

/**
 * Fetch a public key using Web Key Directory
 * @function
 * @param {string} uri - ASPE URI
 * @returns {Promise<Profile>} The fetched profile
 * @example
 * const key = await doip.aspe.fetchASPE('aspe:domain.example:1234567890');
 */
export async function fetchASPE (uri) {
  const re = /aspe:(.*):(.*)/

  if (!re.test(uri)) {
    throw new Error('Invalid ASPE URI')
  }

  const matches = uri.match(re)
  const domainPart = matches[1]
  const localPart = matches[2].toUpperCase()

  const profileUrl = `https://${domainPart}/.well-known/aspe/id/${localPart}`
  let profileJws

  try {
    profileJws = await axios.get(
      profileUrl,
      {
        responseType: 'text'
      }
    )
      .then((/** @type {import('axios').AxiosResponse} */ response) => {
        if (response.status === 200) {
          return response
        }
      })
      .then((/** @type {import('axios').AxiosResponse} */ response) => response.data)
  } catch (e) {
    throw new Error(`Error fetching Keybase key: ${e.message}`)
  }

  const profile = await parseProfileJws(profileJws, uri)
  profile.publicKey.fetch.method = PublicKeyFetchMethod.ASPE
  profile.publicKey.fetch.query = uri
  profile.publicKey.fetch.resolvedUrl = profileUrl

  return profile
}

/**
 * Parse a JWS and extract the profile it contains
 * @function
 * @param {string} profileJws - Compact-Serialized profile JWS
 * @param {string} uri - The ASPE URI associated with the profile
 * @returns {Promise<Profile>} The extracted profile
 * @example
 * const key = await doip.aspe.parseProfileJws('...', 'aspe:domain.example:123');
 */
export async function parseProfileJws (profileJws, uri) {
  const matches = uri.match(/aspe:(.*):(.*)/)
  const localPart = matches[2].toUpperCase()

  // Decode the headers
  const protectedHeader = decodeProtectedHeader(profileJws)

  // Extract the JWK
  if (!SupportedCryptoAlg.includes(protectedHeader.alg)) {
    throw new Error('Invalid profile JWS: wrong key algorithm')
  }
  if (!protectedHeader.kid) {
    throw new Error('Invalid profile JWS: missing key identifier')
  }
  if (!protectedHeader.jwk) {
    throw new Error('Invalid profile JWS: missing key')
  }
  const publicKey = await importJWK(protectedHeader.jwk, protectedHeader.alg)

  // Compute and verify the fingerprint
  const fp = await computeJwkFingerprint(protectedHeader.jwk)

  if (fp !== protectedHeader.kid) {
    throw new Error('Invalid profile JWS: wrong key')
  }
  if (localPart && fp !== localPart) {
    throw new Error('Invalid profile JWS: wrong key')
  }

  // Decode the payload
  const { payload } = await compactVerify(profileJws, publicKey)
  const payloadJson = JSON.parse(new TextDecoder().decode(payload))

  // Verify the payload
  if (!(Object.prototype.hasOwnProperty.call(payloadJson, 'http://ariadne.id/type') && payloadJson['http://ariadne.id/type'] === 'profile')) {
    throw new Error('Invalid profile JWS: JWS is not a profile')
  }
  if (!(Object.prototype.hasOwnProperty.call(payloadJson, 'http://ariadne.id/version') && payloadJson['http://ariadne.id/version'] === 0)) {
    throw new Error('Invalid profile JWS: profile version not supported')
  }

  // Extract data from the payload
  /** @type {string} */
  const profileName = payloadJson['http://ariadne.id/name']
  /** @type {string} */
  const profileDescription = payloadJson['http://ariadne.id/description']
  /** @type {string} */
  const profileThemeColor = payloadJson['http://ariadne.id/color']
  /** @type {Array<string>} */
  const profileClaims = payloadJson['http://ariadne.id/claims']
  /** @type {string} */
  const profileAvatarUrl = payloadJson['http://ariadne.id/avatar_url']

  const profileClaimsParsed = profileClaims.map(x => new Claim(x, uri))

  const pe = new Persona(profileName, profileClaimsParsed)
  if (profileDescription) {
    pe.setDescription(profileDescription)
  }
  if (profileThemeColor && /^#([0-9A-F]{3}){1,2}$/i.test(profileThemeColor)) {
    pe.themeColor = profileThemeColor
  }
  if (profileAvatarUrl) {
    pe.setAvatarUrl(profileAvatarUrl)
  }

  const profile = new Profile(ProfileType.ASP, uri, [pe])
  profile.publicKey.fingerprint = fp
  profile.publicKey.encoding = PublicKeyEncoding.JWK
  profile.publicKey.encodedKey = JSON.stringify(protectedHeader.jwk)
  profile.publicKey.key = protectedHeader.jwk

  switch (protectedHeader.alg) {
    case 'ES256':
      profile.publicKey.keyType = PublicKeyType.ES256
      break

    case 'EdDSA':
      profile.publicKey.keyType = PublicKeyType.EDDSA
      break

    default:
      profile.publicKey.keyType = PublicKeyType.UNKNOWN
      break
  }

  return profile
}

/**
 * Compute the fingerprint for {@link https://github.com/panva/jose/blob/main/docs/interfaces/types.JWK.md JWK} keys
 * @function
 * @param {import('jose').JWK} key - The JWK public key for which to compute the fingerprint
 * @returns {Promise<string>} The computed fingerprint
 */
export async function computeJwkFingerprint (key) {
  const thumbprint = await calculateJwkThumbprint(key, 'sha512')
  const fingerprintBytes = base64url.parse(thumbprint, { loose: true }).slice(0, 16)
  const fingerprint = base32.stringify(fingerprintBytes, { pad: false })

  return fingerprint
}
