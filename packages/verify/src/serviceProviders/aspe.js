/*
Copyright 2024 Yarmo Mackenbach

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
/**
 * ASPE service provider ({@link https://docs.keyoxide.org/service-providers/aspe/|Keyoxide docs})
 * @module serviceProviders/aspe
 * @example
 * import { ServiceProviderDefinitions } from 'doipjs';
 * const sp = ServiceProviderDefinitions.data.aspe.processURI('aspe:domain.example:QPRGVPJNWDXH4ESK2RYDTZJLTE');
 */

import isFQDN from 'validator/lib/isFQDN.js'
import * as E from '../enums.js'
import { ServiceProvider } from '../serviceProvider.js'

const ASPE_PREFIX = 'aspe:'
const FINGERPRINT_PATTERN = /^[A-Z2-7]{26}$/i

export const reURI = /^aspe:([^:/?#\s]+(?::[0-9]{1,5})?):([A-Za-z2-7]{26})$/

/**
 * Parse and validate a canonical ASPE URI.
 * @param {string} uri - ASPE URI to parse
 * @returns {{ authority: string, fingerprint: string } | null} Parsed URI data
 */
export function parseAspeUri (uri) {
  if (typeof uri !== 'string' || !uri.startsWith(ASPE_PREFIX)) {
    return null
  }

  const fingerprintSeparator = uri.lastIndexOf(':')
  if (fingerprintSeparator < ASPE_PREFIX.length) {
    return null
  }

  const authority = uri.slice(ASPE_PREFIX.length, fingerprintSeparator)
  const fingerprint = uri.slice(fingerprintSeparator + 1)
  if (!authority || !FINGERPRINT_PATTERN.test(fingerprint)) {
    return null
  }

  const portSeparator = authority.lastIndexOf(':')
  const hostname = portSeparator === -1
    ? authority
    : authority.slice(0, portSeparator)
  const port = portSeparator === -1
    ? null
    : authority.slice(portSeparator + 1)

  if (port !== null && (!/^\d{1,5}$/.test(port) || Number(port) > 65535)) {
    return null
  }

  if (hostname.toLowerCase() !== 'localhost' && !isFQDN(hostname)) {
    return null
  }

  return {
    authority,
    fingerprint: fingerprint.toUpperCase()
  }
}

/**
 * @function
 * @param {string} uri - Claim URI to process
 * @returns {ServiceProvider} The service provider information based on the claim URI
 */
export function processURI (uri) {
  const parsed = parseAspeUri(uri)
  if (!parsed) {
    return null
  }

  const canonicalUri = `${ASPE_PREFIX}${parsed.authority}:${parsed.fingerprint}`

  return new ServiceProvider({
    about: {
      id: 'aspe',
      name: 'ASPE'
    },
    profile: {
      display: canonicalUri,
      uri: canonicalUri,
      qr: null
    },
    claim: {
      uriRegularExpression: reURI.toString(),
      uriIsAmbiguous: false
    },
    proof: {
      request: {
        uri: null,
        fetcher: E.Fetcher.ASPE,
        accessRestriction: E.ProofAccessRestriction.NONE,
        data: {
          aspeUri: canonicalUri
        }
      },
      response: {
        format: E.ProofFormat.JSON
      },
      target: [{
        format: E.ClaimFormat.URI,
        encoding: E.EntityEncodingFormat.PLAIN,
        relation: E.ClaimRelation.CONTAINS,
        path: ['claims']
      }]
    }
  })
}

export const tests = [
  {
    uri: 'aspe:domain.tld:QPRGVPJNWDXH4ESK2RYDTZJLTE',
    shouldMatch: true
  },
  {
    uri: 'aspe:localhost:8788:qprgvpjnwdxh4esk2rydtzjlte',
    shouldMatch: true
  },
  {
    uri: 'aspe:domain.tld',
    shouldMatch: false
  },
  {
    uri: 'dns:domain.tld',
    shouldMatch: false
  },
  {
    uri: 'https://domain.tld',
    shouldMatch: false
  },
  {
    uri: 'ASPE:domain.tld:QPRGVPJNWDXH4ESK2RYDTZJLTE',
    shouldMatch: false
  },
  {
    uri: 'aspe:domain.tld:QPRGVPJNWDXH4ESK2RYDTZJLTE/path',
    shouldMatch: false
  },
  {
    uri: 'aspe:domain.tld:QPRGVPJNWDXH4ESK2RYDTZJLTE:extra',
    shouldMatch: false
  },
  {
    uri: 'aspe:domain.tld:QPRGVPJNWDXH4ESK2RYDTZJLT0',
    shouldMatch: false
  },
  {
    uri: 'aspe:localhost:999999:QPRGVPJNWDXH4ESK2RYDTZJLTE',
    shouldMatch: false
  }
]
