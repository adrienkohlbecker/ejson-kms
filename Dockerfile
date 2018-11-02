FROM golang:1.11

WORKDIR $GOPATH/src/github.com/adrienkohlbecker/ejson-kms

RUN go get -u github.com/wadey/gocovmerge && \
    go get -u github.com/ngoossens/go-junit-report && \
    go get -u github.com/alecthomas/gometalinter && \
    go get -u github.com/mattn/goveralls && \
    gometalinter --install

ADD . $GOPATH/src/github.com/adrienkohlbecker/ejson-kms
