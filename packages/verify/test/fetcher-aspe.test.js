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
/* eslint-env mocha */
import axios from 'axios'
import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { fn } from '../src/fetcher/aspe.js'

use(chaiAsPromised)

const fingerprint = 'qprgvpjnwdxh4esk2rydtzjlte'
const canonicalFingerprint = fingerprint.toUpperCase()
const publicAspeUri = `aspe:identity.example:${fingerprint}`
const publicAspeUrl = `https://identity.example/.well-known/aspe/id/${canonicalFingerprint}`

/**
 * Invoke a Node-compatible DNS lookup callback as a promise.
 * @param {Function} lookup - Lookup callback supplied to Axios
 * @param {string} hostname - Hostname requested by Axios
 * @param {object|number} options - Node lookup options
 * @returns {Promise<{address: string|Array<object>, family: number|undefined}>} Lookup result
 */
function invokeLookup (lookup, hostname, options) {
  return new Promise((resolve, reject) => {
    lookup(hostname, options, (error, address, family) => {
      if (error) {
        reject(error)
        return
      }
      resolve({ address, family })
    })
  })
}

describe('fetcher.aspe', () => {
  let axiosGet
  let requestedUrls
  let requestOptions
  let fetchError

  beforeEach(() => {
    axiosGet = axios.get
    requestedUrls = []
    requestOptions = []
    fetchError = new Error('ASPE test request intercepted')
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      throw fetchError
    }
  })

  afterEach(() => {
    axios.get = axiosGet
  })

  it('preserves a localhost port and normalizes the fingerprint', async () => {
    const request = fn({
      aspeUri: `aspe:localhost:8788:${fingerprint}`
    }, {
      allowLocalAspe: true
    })

    await expect(request).to.be.rejectedWith(fetchError)
    expect(requestedUrls).to.deep.equal([
      'https://localhost:8788/.well-known/aspe/id/QPRGVPJNWDXH4ESK2RYDTZJLTE'
    ])
  })

  it('rejects localhost by default without requesting it', async () => {
    await expect(fn({
      aspeUri: `aspe:localhost:8788:${fingerprint}`
    })).to.be.rejectedWith(
      'Localhost ASPE requests require opts.allowLocalAspe === true'
    )

    expect(requestedUrls).to.deep.equal([])
  })

  it('constructs the canonical URL for a public authority', async () => {
    const request = fn({
      aspeUri: publicAspeUri
    })

    await expect(request).to.be.rejectedWith(fetchError)
    expect(requestedUrls).to.deep.equal([publicAspeUrl])
  })

  it('rejects malformed and suffixed URIs without requesting them', async () => {
    await expect(fn({
      aspeUri: 'aspe:identity.example:QPRGVPJNWDXH4ESK2RYDTZJLT0'
    })).to.be.rejectedWith('No valid ASPE URI provided')
    await expect(fn({
      aspeUri: `aspe:identity.example:${fingerprint}/profile`
    })).to.be.rejectedWith('No valid ASPE URI provided')

    expect(requestedUrls).to.deep.equal([])
  })

  it('rejects a public redirect to localhost before a second request', async () => {
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      return {
        status: 302,
        headers: {
          location: `https://localhost:8788/.well-known/aspe/id/${canonicalFingerprint}`
        }
      }
    }

    await expect(fn({
      aspeUri: publicAspeUri
    })).to.be.rejectedWith(
      'Localhost ASPE requests require opts.allowLocalAspe === true'
    )
    expect(requestedUrls).to.deep.equal([publicAspeUrl])
  })

  it('follows a safe relative redirect without Axios auto-redirects', async () => {
    const finalUrl = 'https://identity.example/profiles/final?source=aspe'
    const responses = [
      {
        status: 302,
        headers: {
          location: '/profiles/final?source=aspe'
        }
      },
      fetchError
    ]
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      const response = responses.shift()
      if (response instanceof Error) throw response
      return response
    }

    await expect(fn({
      aspeUri: publicAspeUri
    })).to.be.rejectedWith(fetchError)
    expect(requestedUrls).to.deep.equal([publicAspeUrl, finalUrl])
    expect(requestOptions.map(options => options.maxRedirects)).to.deep.equal([0, 0])
  })

  it('rejects a redirect loop', async () => {
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      return {
        status: 302,
        headers: {
          location: requestedUrls.length === 1 ? '/redirect-a' : publicAspeUrl
        }
      }
    }

    await expect(fn({
      aspeUri: publicAspeUri
    })).to.be.rejectedWith('ASPE redirect loop detected')
    expect(requestedUrls).to.deep.equal([
      publicAspeUrl,
      'https://identity.example/redirect-a'
    ])
  })

  it('rejects more than five redirects', async () => {
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      return {
        status: 302,
        headers: {
          location: `/redirect-${requestedUrls.length}`
        }
      }
    }

    await expect(fn({
      aspeUri: publicAspeUri
    })).to.be.rejectedWith('ASPE request exceeded 5 redirects')
    expect(requestedUrls).to.have.length(6)
    expect(requestOptions.every(options => options.maxRedirects === 0)).to.equal(true)
  })

  it('allows localhost redirects only with opt-in and always rejects IPs', async () => {
    const localhostUrl = `https://localhost:8788/.well-known/aspe/id/${canonicalFingerprint}`
    const responses = [
      {
        status: 302,
        headers: {
          location: localhostUrl
        }
      },
      fetchError
    ]
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      const response = responses.shift()
      if (response instanceof Error) throw response
      return response
    }

    await expect(fn({
      aspeUri: publicAspeUri
    }, {
      allowLocalAspe: true
    })).to.be.rejectedWith(fetchError)
    expect(requestedUrls).to.deep.equal([publicAspeUrl, localhostUrl])

    requestedUrls = []
    requestOptions = []
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      return {
        status: 302,
        headers: {
          location: `https://127.0.0.1/.well-known/aspe/id/${canonicalFingerprint}`
        }
      }
    }

    await expect(fn({
      aspeUri: publicAspeUri
    }, {
      allowLocalAspe: true
    })).to.be.rejectedWith('ASPE requests to IP addresses are not allowed')
    expect(requestedUrls).to.deep.equal([publicAspeUrl])
  })

  it('rejects private DNS answers before a connection attempt', async () => {
    for (const address of [
      '127.0.0.1',
      '10.0.0.1',
      '169.254.169.254',
      '::1'
    ]) {
      let connectionAttempted = false
      requestedUrls = []
      requestOptions = []
      axios.get = async (url, options) => {
        requestedUrls.push(url)
        requestOptions.push(options)
        await invokeLookup(options.lookup, new URL(url).hostname, { all: true })
        connectionAttempted = true
        throw fetchError
      }

      await expect(fn({
        aspeUri: publicAspeUri
      }, {
        aspeResolver: async () => [{ address }]
      })).to.be.rejectedWith(
        'ASPE hostname identity.example resolved to a non-global address'
      )
      expect(connectionAttempted).to.equal(false)
      expect(requestedUrls).to.deep.equal([publicAspeUrl])
    }
  })

  it('rejects a mixed public and private DNS answer', async () => {
    let connectionAttempted = false
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      await invokeLookup(options.lookup, new URL(url).hostname, { all: true })
      connectionAttempted = true
      throw fetchError
    }

    await expect(fn({
      aspeUri: publicAspeUri
    }, {
      aspeResolver: async () => [
        { address: '93.184.216.34' },
        { address: '10.0.0.1' }
      ]
    })).to.be.rejectedWith(
      'ASPE hostname identity.example resolved to a non-global address'
    )
    expect(connectionAttempted).to.equal(false)
    expect(requestedUrls).to.deep.equal([publicAspeUrl])
  })

  it('pins a public DNS answer for both Node lookup callback shapes', async () => {
    let resolverCalls = 0
    let lookupAllResult
    let lookupSingleResult
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      const hostname = new URL(url).hostname
      lookupAllResult = await invokeLookup(options.lookup, hostname, { all: true })
      lookupSingleResult = await invokeLookup(options.lookup, hostname, {})
      throw fetchError
    }

    await expect(fn({
      aspeUri: publicAspeUri
    }, {
      aspeResolver: async (hostname) => {
        resolverCalls++
        expect(hostname).to.equal('identity.example')
        return [
          { address: '93.184.216.34' },
          { address: '1.1.1.1' }
        ]
      }
    })).to.be.rejectedWith(fetchError)

    expect(lookupAllResult).to.deep.equal({
      address: [{ address: '93.184.216.34', family: 4 }],
      family: undefined
    })
    expect(lookupSingleResult).to.deep.equal({
      address: '93.184.216.34',
      family: 4
    })
    expect(resolverCalls).to.equal(1)
  })

  it('does not let localhost opt-in allow private DNS for an FQDN', async () => {
    let connectionAttempted = false
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      await invokeLookup(options.lookup, new URL(url).hostname, { all: true })
      connectionAttempted = true
      throw fetchError
    }

    await expect(fn({
      aspeUri: publicAspeUri
    }, {
      allowLocalAspe: true,
      aspeResolver: async () => [{ address: '10.0.0.1' }]
    })).to.be.rejectedWith(
      'ASPE hostname identity.example resolved to a non-global address'
    )
    expect(connectionAttempted).to.equal(false)
    expect(requestedUrls).to.deep.equal([publicAspeUrl])
  })

  it('allows opted-in localhost to pin a loopback DNS answer', async () => {
    let lookupResult
    axios.get = async (url, options) => {
      requestedUrls.push(url)
      requestOptions.push(options)
      lookupResult = await invokeLookup(options.lookup, new URL(url).hostname, {
        all: true
      })
      throw fetchError
    }

    await expect(fn({
      aspeUri: `aspe:localhost:8788:${fingerprint}`
    }, {
      allowLocalAspe: true,
      aspeResolver: async () => [
        { address: '127.0.0.1' },
        { address: '::1' }
      ]
    })).to.be.rejectedWith(fetchError)
    expect(lookupResult).to.deep.equal({
      address: [{ address: '127.0.0.1', family: 4 }],
      family: undefined
    })
    expect(requestedUrls).to.deep.equal([
      `https://localhost:8788/.well-known/aspe/id/${canonicalFingerprint}`
    ])
  })
})
