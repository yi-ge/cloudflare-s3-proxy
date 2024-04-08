import { AwsClient } from 'aws4fetch'

export function SignatureMissingException() {
}


export function SignatureInvalidException() {
}

// Function to extract chunk data from the ArrayBuffer
function extractChunkData(mixedBuffer) {
  const arrayBuffer = new Uint8Array(mixedBuffer)
  const decoder = new TextDecoder();
  let chunkData = []
  let i = 0
  while (i < arrayBuffer.length) {
    // Find the end index of the chunk header
    let headerEndIndex = -1
    for (let j = i; j < arrayBuffer.length - 1; j++) {
      if (arrayBuffer[j] === 13 && arrayBuffer[j + 1] === 10) { // ASCII for '\r\n'
        headerEndIndex = j
        break
      }
    }
    if (headerEndIndex === -1) break // No more headers found
    // Parse the chunk size and signature from the header
    let header = decoder.decode(arrayBuffer.slice(i, headerEndIndex))
    let [chunkSizeHex, signature] = header.split(';chunk-signature=')
    let chunkSize = parseInt(chunkSizeHex, 16)
    if (chunkSize === 0) {
      break
    }
    // Extract chunk data
    let dataStartIndex = headerEndIndex + 2 // Start after the '\r\n'
    let dataEndIndex = dataStartIndex + chunkSize
    chunkData.push(arrayBuffer.slice(dataStartIndex, dataEndIndex))
    // Move to the next chunk
    i = dataEndIndex + 2 // Skip the '\r\n'
  }
  return chunkData
}
function removeChunkSignature(mixedBuffer) {
  //loop through buffer
  let extractedChunks = extractChunkData(mixedBuffer)

  let totalLength = extractedChunks.reduce((acc, chunk) => acc + chunk.byteLength, 0)
  let combinedBuffer = new Uint8Array(totalLength)
  let offset = 0
  for (let chunk of extractedChunks) {
    combinedBuffer.set(chunk, offset)
    offset += chunk.byteLength
  }
  return combinedBuffer.buffer
}
function encodeRfc3986(urlEncodedStr) {
  return urlEncodedStr.replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())
}


function parseAuthorizationInfo(request) {
  const url = new URL(request.url)
  let credential = null, signedHeaders = null, signature = null
  if (request.headers.get('Authorization')) {
    const authorization = request.headers.get('Authorization')
    const re = /^AWS4-HMAC-SHA256 Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=(.+)$/;
    [, credential, signedHeaders, signature] = authorization.match(re)
    credential = credential.split('/')
    signedHeaders = signedHeaders.split(';')
  } else {
    if (url.searchParams.has('X-Amz-Credential') &&
      url.searchParams.has('X-Amz-SignedHeaders') &&
      url.searchParams.has('X-Amz-Signature')) {
      credential = url.searchParams.get('X-Amz-Credential').split('/')
      signedHeaders = url.searchParams.get('X-Amz-SignedHeaders').split(';')
      signature = url.searchParams.get('X-Amz-Signature')
    }
  }
  if (!credential || !signedHeaders || !signature) {
    throw new SignatureMissingException()
  }
  return { credential, signedHeaders, signature }
}
export class AwsProxy {
	constructor(request, env) {
		this.request = request
		this.env = env
	}
  getAwsClient() {
    const { credential, signedHeaders, signature } = parseAuthorizationInfo(this.request)
    this.credential = credential;
    this.signature = signature;
    const signed_region = credential[2]
    if (!signedHeaders || !credential || !signature || !signed_region) {
      throw new SignatureMissingException()
    }
    this.signedHeaders = signedHeaders
      .map(key => ({
        name: key,
        value: this.request.headers.get(key),
      }))
      .reduce((obj, item) => (obj[item.name] = item.value, obj), {})
    return this.aws = new AwsClient({
      'accessKeyId': this.env.S3_ACCESS_KEY_ID,
      'secretAccessKey': this.env.S3_SECRET_ACCESS_KEY,
      'service': 's3',
      'region': signed_region,
    })
  }
  async verifySignature() {
    this.getAwsClient();
    if (this.credential[0] !== this.env.S3_ACCESS_KEY_ID) {
      throw new SignatureInvalidException()
    }

    const headersToSign = Object.assign({}, this.signedHeaders)

    // Sign the request using the same key
    let generatedSignature
    if (this.request.headers.get('Authorization')) {
      const signedRequest = await this.aws.sign(this.request.url, {
        method: this.request.method,
        headers: headersToSign,
        body: this.request.body,
        aws: { datetime: headersToSign['x-amz-date'], allHeaders: true },
      })
      generatedSignature = parseAuthorizationInfo(signedRequest).signature
    } else {
      const signedRequest = await this.signUrl(this.request)
      generatedSignature = parseAuthorizationInfo(signedRequest).signature
    }

    if (this.signature !== generatedSignature) {
      throw new SignatureInvalidException()
    }

  }
  async signUrl(request, method = null) {
    let urlToSign
    if (request instanceof Request) {
      urlToSign = new URL(request.url)
      if(!method){
        method=request.method
      }
    } else {
      urlToSign = new URL(request)
    }
    urlToSign.searchParams.delete('X-Amz-Signature');
    urlToSign.searchParams.delete('X-Amz-Credential');
    let signedRequest = await this.aws.sign(urlToSign, {
      method: method || 'GET',
      signQuery: true,
      aws: {
        datetime: urlToSign.searchParams.get('X-Amz-Date'),
      },
    })
    let url = new URL(signedRequest.url)
    const seenKeys = new Set()
    url.search = [...url.searchParams]
      .filter(([k]) => {
        if (!k) return false
        if (this.aws.service === 's3') {
          if (seenKeys.has(k)) return false
          seenKeys.add(k)
        }
        return true
      })
      .map(pair => pair.map(p => encodeRfc3986(encodeURIComponent(p))))
      .sort(([k1, v1], [k2, v2]) => k1 < k2 ? -1 : k1 > k2 ? 1 : v1 < v2 ? -1 : v1 > v2 ? 1 : 0)
      .map(pair => pair.join('='))
      .join('&')
    signedRequest = new Request(url, signedRequest)
    return signedRequest

  }
  async fetch() {
    let url = new URL(this.request.url)
    url.hostname = this.env.S3_ENDPOINT
    if (url.searchParams.has('X-Amz-Signature')) {
      //Got a signed url
      const signed = await this.signUrl(url)
      return fetch(signed.url)
    }

    let headersToSign = Object.assign({}, this.signedHeaders)

    let filteredBody = null
    if (this.request.method === 'GET' || this.request.method === 'HEAD') {
      filteredBody = this.request.body
    } else {
      if (headersToSign['x-amz-content-sha256'] === 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD') {
        const body = await this.request.arrayBuffer()
        filteredBody = removeChunkSignature(body)
        headersToSign['x-amz-content-sha256'] = 'UNSIGNED-PAYLOAD'
        headersToSign['content-length'] = filteredBody.byteLength
      } else {
        filteredBody = this.request.body
      }


    }

    // Sign the new request
    let signedRequest = await this.aws.sign(url.toString(), {
      method: this.request.method,
      headers: headersToSign,
      body: filteredBody,
      aws: {
        datetime: headersToSign['x-amz-date'],
        allHeaders: true,
      },
    })

    if (signedRequest.method === 'HEAD') {
      const noHeadExtensions = [
        "7z", "csv", "gif", "midi", "png", "tif", "zip",
        "avi", "doc", "gz", "mkv", "ppt", "tiff", "zst",
        "avif", "docx", "ico", "mp3", "pptx", "ttf",
        "apk", "dmg", "iso", "mp4", "ps", "webm",
        "bin", "ejs", "jar", "ogg", "rar", "webp",
        "bmp", "eot", "jpg", "otf", "svg", "woff",
        "bz2", "eps", "jpeg", "pdf", "svgz", "woff2",
        "class", "exe", "js", "pict", "swf", "xls",
        "css", "flac", "mid", "pls", "tar", "xlsx"
      ];
      //Check if url path ends with any of the extensions
      let isNoHead = noHeadExtensions.some(ext => url.pathname.toLowerCase().endsWith('.' + ext))
      if (isNoHead) {//HEAD not supported for these extensions
        let signedUrl = await this.signUrl(url, 'GET')
        //Sign url as GET amd send it
        const response= fetch(signedUrl.url, { method: 'HEAD' })
        //Ignore body
        return new Response(null, { status: response.status, headers: response.headers })
      }
    }
    return fetch(signedRequest)
  }

}