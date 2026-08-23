# SAG as a Lambda function, in the image AWS would run it in.
#
# The AWS base image carries the Node runtime interface client and, for local
# use, the runtime interface emulator: with no AWS_LAMBDA_RUNTIME_API set, the
# image's entrypoint starts the emulator on port 8080 and waits for
# invocations. So this container is not a Lambda-shaped Node process - it is
# the same runtime, loading the same handler, from the same image an operator
# would push to ECR.
#
# Nothing in front of it speaks HTTP, which is why the stack also runs
# front-door.js: see test/local-stack/lambda/front-door.js.
#
# Built from the repository root.

FROM public.ecr.aws/lambda/nodejs:24

# "type": "module" is what lets the runtime load an ES module handler.
COPY package.json ${LAMBDA_TASK_ROOT}/
COPY src ${LAMBDA_TASK_ROOT}/src
COPY adapters ${LAMBDA_TASK_ROOT}/adapters

# Everything else - the issuer, the KMS key, the table, the bucket - arrives as
# environment variables, exactly as it would from the function's configuration.
CMD ["adapters/lambda/handler.handler"]
