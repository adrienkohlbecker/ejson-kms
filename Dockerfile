FROM golang:1.7

ENV GOPATH /gopath
ENV PATH /gopath/bin:$PATH

WORKDIR /gopath/src/github.com/adrienkohlbecker/ejson-kms

RUN go get -u github.com/wadey/gocovmerge && \
    go get -u github.com/ngoossens/go-junit-report && \
    go get -u github.com/alecthomas/gometalinter && \
    go get -u github.com/mattn/goveralls && \
    gometalinter --install

ADD . /gopath/src/github.com/adrienkohlbecker/ejson-kms
