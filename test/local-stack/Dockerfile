# Everything in the local stack that is a small Node process.
#
# The mock AWS services, the API Gateway stand-in in front of the Lambda
# emulator, and the stub relying parties are all plain Node with no
# dependencies, so they share one image and differ only in their command. One
# build, one layer cache, and nothing to install.
#
# Built from the repository root, because the mocks import SAG's own Signature
# Version 4 signer to check the signatures SAG sends.

FROM node:24-alpine

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787

WORKDIR /srv/sag

# "type": "module", which is what makes the imports below resolve.
COPY package.json ./
COPY src ./src
COPY examples ./examples
COPY test/local-stack ./test/local-stack

USER node

# Each service in compose.yml sets its own command.
CMD ["node", "--version"]
