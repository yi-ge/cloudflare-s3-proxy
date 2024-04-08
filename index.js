import {AwsProxy, SignatureMissingException} from './proxy'

const unsignedError =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Unauthenticated requests are not allowed for this api</Message>
</Error>`

// Could add more detail regarding the specific error, but this enough for now
const validationError =
    `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error>
    <Type>Sender</Type>
    <Code>SignatureDoesNotMatch</Code>
    <Message>Signature validation failed.</Message>
  </Error>
  <RequestId>0300D815-9252-41E5-B587-F189759A21BF</RequestId>
</ErrorResponse>`


export default {
    async fetch(request, env) {
        const awsProxy = new AwsProxy(request, env)
        // Only handle requests signed by our configured key.
        try {
            await awsProxy.verifySignature();
        } catch (e) {
            // Signature is missing or bad - deny the request
            return new Response(
                (e instanceof SignatureMissingException) ?
                    unsignedError :
                    validationError,
                {
                    status: 403,
                    headers: {
                        'Content-Type': 'application/xml',
                        'Cache-Control': 'max-age=0, no-cache, no-store',
                    },
                })
        }

        return awsProxy.fetch();
    },
};
