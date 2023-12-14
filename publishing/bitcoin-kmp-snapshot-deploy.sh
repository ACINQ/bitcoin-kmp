#!/bin/bash -x

GROUP_ID=fr.acinq.bitcoin
ARTIFACT_ID_BASE=bitcoin-kmp

if [[ -z "${VERSION}" ]]; then
  echo "VERSION is not defined"
  exit 1
fi

cd snapshot
pushd .
cd fr/acinq/bitcoin/bitcoin-kmp/$VERSION
mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
  -DpomFile=$ARTIFACT_ID_BASE-$VERSION.pom \
  -Dfile=$ARTIFACT_ID_BASE-$VERSION.jar \
  -Dfiles=$ARTIFACT_ID_BASE-$VERSION.module,$ARTIFACT_ID_BASE-$VERSION-kotlin-tooling-metadata.json \
  -Dtypes=module,json \
  -Dclassifiers=,kotlin-tooling-metadata \
  -Dsources=$ARTIFACT_ID_BASE-$VERSION-sources.jar \
  -Djavadoc=$ARTIFACT_ID_BASE-$VERSION-javadoc.jar
popd
pushd .
for i in iosarm64 iossimulatorarm64 iosx64 jvm linuxx64; do
  cd fr/acinq/bitcoin/bitcoin-kmp-$i/$VERSION
  if [ $i == iosarm64 ] || [ $i == iossimulatorarm64 ] || [ $i == iosx64 ]; then
    mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
      -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
      -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
      -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION-metadata.jar,$ARTIFACT_ID_BASE-$i-$VERSION.module,$ARTIFACT_ID_BASE-$i-$VERSION-cinterop-CoreCrypto.klib \
      -Dtypes=jar,module,klib \
      -Dclassifiers=metadata,,cinterop-CoreCrypto \
      -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
      -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
  elif [ $i == linuxx64 ]; then
    mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
      -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
      -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
      -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
      -Dtypes=module \
      -Dclassifiers= \
      -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
      -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
  else
    mvn deploy:deploy-file -DrepositoryId=ossrh -Durl=https://oss.sonatype.org/content/repositories/snapshots/ \
      -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
      -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.jar \
      -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
      -Dtypes=module \
      -Dclassifiers= \
      -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
      -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
  fi
  popd
  pushd .
done
