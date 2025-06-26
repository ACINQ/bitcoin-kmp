#!/bin/bash -x
#
# first you must sign all files with something like:
# find release -type f -print -exec gpg -ab {} \;
#

if [[ -z "${VERSION}" ]]; then
  echo "VERSION is not defined"
  exit 1
fi

if [[ -z "${CENTRAL_TOKEN_GPG_FILE}" ]]; then
  echo "CENTRAL_TOKEN_GPG_FILE is not defined"
  exit 1
fi

CENTRAL_TOKEN=$(gpg --decrypt $CENTRAL_TOKEN_GPG_FILE)

pushd .
cd release
for i in 	bitcoin-kmp \
		bitcoin-kmp-iosarm64 \
		bitcoin-kmp-iossimulatorarm64 \
		bitcoin-kmp-iosx64 \
		bitcoin-kmp-jvm \
		bitcoin-kmp-linuxx64 \
		bitcoin-kmp-linuxarm64 \
		bitcoin-kmp-macosarm64 \
		bitcoin-kmp-macosx64
do
	DIR=fr/acinq/bitcoin/$i/$VERSION
	case $1 in
	  create)
  	  for file in $DIR/*
	    do
	      sha1sum $file | sed 's/ .*//' > $file.sha1
	      md5sum $file | sed 's/ .*//' > $file.md5
	      gpg -ab $file
      done
	    zip -r $i.zip $DIR
	  ;;
  	upload)
	    curl --request POST --verbose --header "Authorization: Bearer ${CENTRAL_TOKEN}" --form bundle=@$i.zip https://central.sonatype.com/api/v1/publisher/upload
    ;;
  esac
done
popd