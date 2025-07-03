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
mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
  -DpomFile=$ARTIFACT_ID_BASE-$VERSION.pom \
  -Dfile=$ARTIFACT_ID_BASE-$VERSION.jar \
  -Dfiles=$ARTIFACT_ID_BASE-$VERSION.module,$ARTIFACT_ID_BASE-$VERSION-kotlin-tooling-metadata.json \
  -Dtypes=module,json \
  -Dclassifiers=,kotlin-tooling-metadata \
  -Dsources=$ARTIFACT_ID_BASE-$VERSION-sources.jar \
  -Djavadoc=$ARTIFACT_ID_BASE-$VERSION-javadoc.jar
popd
pushd .
for i in iosarm64 iossimulatorarm64 iosx64 macosarm64 macosx64 jvm linuxx64 linuxarm64; do
  cd fr/acinq/bitcoin/bitcoin-kmp-$i/$VERSION

  case $i in
    iosarm64 |iossimulatorarm64 | iosx64)
      mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION-metadata.jar,$ARTIFACT_ID_BASE-$i-$VERSION.module,$ARTIFACT_ID_BASE-$i-$VERSION-cinterop-CoreCrypto.klib \
        -Dtypes=jar,module,klib \
        -Dclassifiers=metadata,,cinterop-CoreCrypto \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
    macosarm64 | macosx64)
      mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION-metadata.jar,$ARTIFACT_ID_BASE-$i-$VERSION.module \
        -Dtypes=jar,module \
        -Dclassifiers=metadata, \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
    linuxx64 | linuxarm64)
      mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.klib \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
        -Dtypes=module \
        -Dclassifiers= \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
    *)
      mvn deploy:deploy-file -DrepositoryId=central_portal -Durl=https://central.sonatype.com/repository/maven-snapshots/ \
        -DpomFile=$ARTIFACT_ID_BASE-$i-$VERSION.pom \
        -Dfile=$ARTIFACT_ID_BASE-$i-$VERSION.jar \
        -Dfiles=$ARTIFACT_ID_BASE-$i-$VERSION.module \
        -Dtypes=module \
        -Dclassifiers= \
        -Dsources=$ARTIFACT_ID_BASE-$i-$VERSION-sources.jar \
        -Djavadoc=$ARTIFACT_ID_BASE-$i-$VERSION-javadoc.jar
      ;;
  esac
  popd
  pushd .
done
