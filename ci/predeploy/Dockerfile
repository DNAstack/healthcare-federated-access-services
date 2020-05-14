FROM golang:1.14-stretch

ADD target/ ./
ENV GOPATH="/go/gcp"

# PROJECT must be set to the GCP project with the datastore
# "dam" or "ic" should be specificed as a command
# The permissions file must be mounted at /go/deploy/config/(dam|ic)/permissions_master_main_latest.json
ENTRYPOINT ["./import.bash", "-t", "permission"]
