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
 * Fetch proofs from Profile obtained through ASPE
 * @module fetcher/aspe
 * @example
 * import { fetcher } from 'doipjs';
 * const data = await fetcher.aspe.fn({ aspeUri: 'aspe:domain.example:abc123def456' });
 */
import axios from 'axios'
import { isNode } from 'browser-or-node'
import isFQDN from 'validator/lib/isFQDN.js'
import isIP from 'validator/lib/isIP.js'
import { version } from '../constants.js'
import { parseProfileJws } from '../asp.js'
import { parseAspeUri } from '../serviceProviders/aspe.js'

/**
 * Default timeout after which the fetch is aborted
 * @constant
 * @type {number}
 * @default 5000
 */
export const timeout = 5000

const maxRedirects = 5
const nodeDnsModule = 'node:dns/promises'
const nodeNetModule = 'node:net'

let nodeNetworkToolsPromise

/**
 * Load Node networking primitives without including them in browser bundles.
 * @returns {Promise<object>} DNS resolver and address classification tools
 */
async function getNodeNetworkTools () {
  if (!nodeNetworkToolsPromise) {
    nodeNetworkToolsPromise = Promise.all([
      import(nodeDnsModule),
      import(nodeNetModule)
    ]).then(([dns, net]) => {
      const blockedIpv4 = new net.BlockList()
      const blockedIpv6 = new net.BlockList()
      const loopbackIpv4 = new net.BlockList()
      const loopbackIpv6 = new net.BlockList()
      const globalIpv6 = new net.BlockList()

      for (const [network, prefix, family] of [
        ['0.0.0.0', 8, 'ipv4'],
        ['10.0.0.0', 8, 'ipv4'],
        ['100.64.0.0', 10, 'ipv4'],
        ['127.0.0.0', 8, 'ipv4'],
        ['169.254.0.0', 16, 'ipv4'],
        ['172.16.0.0', 12, 'ipv4'],
        ['192.0.0.0', 24, 'ipv4'],
        ['192.0.2.0', 24, 'ipv4'],
        ['192.88.99.0', 24, 'ipv4'],
        ['192.168.0.0', 16, 'ipv4'],
        ['198.18.0.0', 15, 'ipv4'],
        ['198.51.100.0', 24, 'ipv4'],
        ['203.0.113.0', 24, 'ipv4'],
        ['224.0.0.0', 4, 'ipv4'],
        ['240.0.0.0', 4, 'ipv4'],
        ['::', 96, 'ipv6'],
        ['::ffff:0:0', 96, 'ipv6'],
        ['64:ff9b::', 96, 'ipv6'],
        ['64:ff9b:1::', 48, 'ipv6'],
        ['100::', 64, 'ipv6'],
        ['2001::', 23, 'ipv6'],
        ['2001:db8::', 32, 'ipv6'],
        ['2002::', 16, 'ipv6'],
        ['3fff::', 20, 'ipv6'],
        ['fc00::', 7, 'ipv6'],
        ['fe80::', 10, 'ipv6'],
        ['ff00::', 8, 'ipv6']
      ]) {
        const blockList = family === 'ipv4' ? blockedIpv4 : blockedIpv6
        blockList.addSubnet(network, prefix, family)
      }

      loopbackIpv4.addSubnet('127.0.0.0', 8, 'ipv4')
      loopbackIpv6.addAddress('::1', 'ipv6')
      globalIpv6.addSubnet('2000::', 3, 'ipv6')

      return {
        blockedIpv4,
        blockedIpv6,
        globalIpv6,
        isIp: net.isIP,
        lookup: dns.lookup,
        loopbackIpv4,
        loopbackIpv6
      }
    })
  }
  return await nodeNetworkToolsPromise
}

/**
 * Resolve a hostname using Node's operating-system resolver.
 * @param {string} hostname - Hostname to resolve
 * @returns {Promise<Array<{address: string, family: number}>>} Resolved addresses
 */
async function resolveNodeHostname (hostname) {
  const { lookup } = await getNodeNetworkTools()
  return await lookup(hostname, { all: true, verbatim: true })
}

/**
 * Resolve and validate every address before selecting one for the socket.
 * @param {string} hostname - Expected request hostname
 * @param {boolean} allowLocalAspe - Whether literal localhost is allowed
 * @param {Function} resolver - Hostname resolver
 * @param {number} [requestedFamily] - Optional address family requested by Node
 * @returns {Promise<{address: string, family: number}>} A pinned safe address
 */
async function resolveSafeAddress (hostname, allowLocalAspe, resolver, requestedFamily) {
  const tools = await getNodeNetworkTools()
  const resolved = await resolver(hostname)
  const records = (Array.isArray(resolved) ? resolved : [resolved])
    .map(record => typeof record === 'string' ? { address: record } : record)
    .map(record => ({
      address: record?.address,
      family: tools.isIp(record?.address ?? '')
    }))

  if (!records.length || records.some(record => !record.family)) {
    throw new Error(`ASPE hostname ${hostname} did not resolve to valid IP addresses`)
  }

  const isLocalhost = hostname.toLowerCase() === 'localhost'
  for (const record of records) {
    const family = record.family === 4 ? 'ipv4' : 'ipv6'
    const isLoopback = record.family === 4
      ? tools.loopbackIpv4.check(record.address, family)
      : tools.loopbackIpv6.check(record.address, family)
    const isGlobal = record.family === 4
      ? !tools.blockedIpv4.check(record.address, family)
      : tools.globalIpv6.check(record.address, family) &&
        !tools.blockedIpv6.check(record.address, family)

    if ((isLocalhost && (!allowLocalAspe || !isLoopback)) ||
      (!isLocalhost && !isGlobal)) {
      throw new Error(`ASPE hostname ${hostname} resolved to a non-global address`)
    }
  }

  const selected = requestedFamily
    ? records.find(record => record.family === requestedFamily)
    : records[0]
  if (!selected) {
    throw new Error(`ASPE hostname ${hostname} has no address in the requested family`)
  }
  return selected
}

/**
 * Create a Node lookup callback that pins one pre-validated DNS result.
 * @param {string} expectedHostname - Hostname expected from the request URL
 * @param {boolean} allowLocalAspe - Whether literal localhost is allowed
 * @param {Function} resolver - Hostname resolver
 * @returns {Function} Node-compatible lookup callback
 */
function createSafeLookup (expectedHostname, allowLocalAspe, resolver) {
  const resolutions = new Map()

  return (hostname, options, callback) => {
    if (hostname.toLowerCase() !== expectedHostname.toLowerCase()) {
      callback(new Error('ASPE DNS lookup hostname did not match the request URL'))
      return
    }

    const requestedFamily = typeof options === 'number'
      ? options
      : options?.family
    const cacheKey = requestedFamily || 0
    if (!resolutions.has(cacheKey)) {
      resolutions.set(cacheKey, resolveSafeAddress(
        expectedHostname,
        allowLocalAspe,
        resolver,
        requestedFamily
      ))
    }

    resolutions.get(cacheKey)
      .then(selected => {
        if (typeof options === 'object' && options?.all) {
          callback(null, [selected])
          return
        }
        callback(null, selected.address, selected.family)
      })
      .catch(error => callback(error))
  }
}

/**
 * Validate a URL before an ASPE network request.
 * @param {URL} url - URL to validate
 * @param {boolean} allowLocalAspe - Whether localhost requests are explicitly allowed
 * @returns {URL} The validated URL
 */
function validateRequestUrl (url, allowLocalAspe) {
  if (url.protocol !== 'https:') {
    throw new Error('ASPE requests must use HTTPS')
  }
  if (url.username || url.password) {
    throw new Error('ASPE request URLs must not include credentials')
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (hostname === 'localhost') {
    if (!allowLocalAspe) {
      throw new Error('Localhost ASPE requests require opts.allowLocalAspe === true')
    }
    return url
  }
  if (isIP(hostname)) {
    throw new Error('ASPE requests to IP addresses are not allowed')
  }
  if (!isFQDN(hostname)) {
    throw new Error('ASPE requests require a valid fully qualified domain name')
  }

  return url
}

/**
 * Fetch an ASPE response while validating every redirect target.
 * @param {string} initialUrl - Initial ASPE endpoint URL
 * @param {boolean} allowLocalAspe - Whether localhost requests are explicitly allowed
 * @param {Function} resolver - Node hostname resolver
 * @returns {Promise<object>} The final Axios response
 */
async function fetchWithValidatedRedirects (initialUrl, allowLocalAspe, resolver) {
  let currentUrl = validateRequestUrl(new URL(initialUrl), allowLocalAspe)
  const visitedUrls = new Set([currentUrl.href])

  for (let redirectCount = 0; ; redirectCount++) {
    const lookup = isNode
      ? createSafeLookup(currentUrl.hostname, allowLocalAspe, resolver)
      : undefined
    const response = await axios.get(currentUrl.href, {
      headers: {
        Accept: 'application/asp+jwt',
        'User-Agent': `doipjs/${version}`
      },
      ...(lookup ? { lookup } : {}),
      maxRedirects: 0,
      validateStatus: (status) => status >= 200 && status < 400
    })

    if (response.status < 300) {
      return response
    }
    if (redirectCount >= maxRedirects) {
      throw new Error(`ASPE request exceeded ${maxRedirects} redirects`)
    }

    const location = typeof response.headers?.get === 'function'
      ? response.headers.get('location')
      : response.headers?.location
    if (typeof location !== 'string' || !location.trim()) {
      throw new Error('ASPE redirect response is missing a valid Location header')
    }

    let nextUrl
    try {
      nextUrl = validateRequestUrl(new URL(location, currentUrl), allowLocalAspe)
    } catch (error) {
      if (error instanceof TypeError) {
        throw new Error('ASPE redirect response contains an invalid Location header')
      }
      throw error
    }

    if (visitedUrls.has(nextUrl.href)) {
      throw new Error('ASPE redirect loop detected')
    }
    visitedUrls.add(nextUrl.href)
    currentUrl = nextUrl
  }
}

/**
 * Execute a fetch request
 * @function
 * @param {object} data - Data used in the request
 * @param {string} data.aspeUri - ASPE URI of the targeted profile
 * @param {number} [data.fetcherTimeout] - Optional timeout for the fetcher
 * @param {import('../types').VerificationConfig} [opts] - Options used to enable the request
 * @param {boolean} [opts.allowLocalAspe] - Explicitly allow an ASPE request to localhost
 * @param {Function} [opts.aspeResolver] - Optional Node hostname resolver for deterministic testing
 * @returns {Promise<object>} The fetched claims from an ASP profile
 */
export async function fn (data, opts) {
  let timeoutHandle
  const timeoutPromise = new Promise((resolve, reject) => {
    timeoutHandle = setTimeout(
      () => reject(new Error('Request was timed out')),
      data.fetcherTimeout ? data.fetcherTimeout : timeout
    )
  })

  const fetchPromise = new Promise((resolve, reject) => {
    const parsedUri = parseAspeUri(data.aspeUri)

    if (!parsedUri) {
      reject(new Error('No valid ASPE URI provided'))
      return
    }

    const url = `https://${parsedUri.authority}/.well-known/aspe/id/${parsedUri.fingerprint}`

    const resolver = opts?.aspeResolver ?? resolveNodeHostname
    if (typeof resolver !== 'function') {
      reject(new Error('opts.aspeResolver must be a function'))
      return
    }

    fetchWithValidatedRedirects(url, opts?.allowLocalAspe === true, resolver)
      .then(async res => await parseProfileJws(res.data, data.aspeUri))
      .then(profile =>
        profile.personas.flatMap(p => { return p.claims.map(c => c._uri) })
      )
      .then(res => {
        resolve({
          claims: res
        })
      })
      .catch(e => {
        reject(e)
      })
  })

  return Promise.race([fetchPromise, timeoutPromise]).finally(() => {
    clearTimeout(timeoutHandle)
  })
}
