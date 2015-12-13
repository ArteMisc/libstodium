#!/bin/bash
set -e
set -x

# Android NDK r10e
export NDK_VERSION="android-ndk-r10e"

# Require JAVA_HOME
if [ -z "$JAVA_HOME" ]; then
    echo "ERROR You should set JAVA_HOME"
    echo "example: \`export JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64\`"
    echo "Exiting!"
    exit 1
fi

function ndk_setup {
    ARCH=$(uname -m)
    if [ $ARCH != "x86_64" ]; then
      $ARCH = "x86"
    fi

    echo "Downloading NDK for ${ARCH}"
    BIN="${NDK_VERSION}-linux-${ARCH}.bin"
    echo "Downloading from http://dl.google.com/android/ndk/${BIN}"

    wget http://dl.google.com/android/ndk/$BIN
    chmod a+x $BIN
    ./$BIN

    export ANDROID_NDK_HOME=${PWD}/${NDK_VERSION}
}

function ndk_cleanup {
    rm -rf ${NDK_VERSION}* 
}

#
# SWIG 2.0
#
function swig_setup {
    cd jni

    wget http://prdownloads.sourceforge.net/swig/swig-2.0.10.tar.gz
    tar -xvf swig-2.0.10.tar.gz
    
    cd swig-2.0.10

    ./configure
    make -j 5
    sudo make install

    cd ../..
}

function swig_cleanup {
    cd jni

    rm -rf swig-2.0.10*

    cd ..
}

#
# install libsodium from the repository
#
function setup_libsodium {
    rm -rf libsodium

    git submodule init
    git submodule update

    cd libsodium

    # use stable branch
    # git fetch && git checkout origin/stable

    ./autogen.sh

    # Build local
    ./configure
    make && make check
    sudo make install

    # Build android
    ./dist-build/android-arm.sh
    ./dist-build/android-armv7-a.sh
    ./dist-build/android-mips32.sh
    ./dist-build/android-x86.sh
    cd ..
}

# Install swig and compile the JNI with libsodium
function compile_jni {
    cd jni
    ./compile.sh

    export PATH=$PATH:$ANDROID_NDK_HOME
    ndk-build clean
    ndk-build
    cd ..
}

# Add auto-cleanup before the script runs
ndk_cleanup
swig_cleanup

# Download and install
ndk_setup
swig_setup

# Compile the libraries
setup_libsodium
compile_jni

# Cleanup
ndk_cleanup
swig_cleanup
