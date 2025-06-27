FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-okta-aws-federation"]
COPY baton-okta-aws-federation /