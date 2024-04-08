# Cloudflare Worker S3 Compatible Proxy

Proxy S3 compatible API requests.

* Incoming requests must be signed with the same credentials that you configure in the worker. The worker validates the AWS V4 signature on all downstream (incoming) requests and then signs the upstream (outgoing) request.
* Limitations: upload size limit is about 80MB due to Cloudflare's 100MB limit on request body size. This can be increased by using the `stream` API, but this is not implemented in this worker.

Informal testing suggests that there is negligible performance overhead imposed by the signature verification and resigning.

## Configuration

You must configure `S3_ACCESS_KEY_ID` and `S3_ENDPOINT` in `wrangler.toml`.

```toml
[vars]
AWS_ACCESS_KEY_ID = "<your s3 compatible key id>"
AWS_S3_ENDPOINT = "<your S3 endpoint - e.g. s3.us-west-001.backblazeb2.com >"

```

You must also configure `S3_SECRET_ACCESS_KEY` as a [secret](https://blog.cloudflare.com/workers-secrets-environment/):

```bash
echo "<your s3 compatible secret key>" | wrangler secret put S3_SECRET_ACCESS_KEY
```



## Wrangler

You can use this repository as a template for your own worker using [`wrangler`](https://github.com/cloudflare/wrangler):

```bash
wrangler generate projectname https://github.com/as247/cloudflare-s3-proxy
```

