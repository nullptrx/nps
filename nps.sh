#!/bin/bash

menu="Please select a building option for your NPS.:
1. MacOS amd64
2. MacOS arm64
3. Windows amd64
4. Windows arm64
5. Linux amd64
6. Linux arm64
*. Quit"

echo "$menu"
read -p "Select an option [1-7]: " option
case $option in
    1) GOOS="darwin" GOARCH="amd64";;
    2) GOOS="darwin" GOARCH="arm64";;
    3) GOOS="windows" GOARCH="amd64";;
    4) GOOS="windows" GOARCH="arm64";;
    5) GOOS="linux" GOARCH="amd64";;
    6) GOOS="linux" GOARCH="arm64";;
    *) echo "Invalid option" && exit;;
esac

echo "Compiling for $GOOS-$GOARCH..."
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -o build/ github.com/djylb/nps/cmd/nps
echo "Compiled."