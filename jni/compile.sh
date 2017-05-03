set -e

if [ -z "$JAVA_HOME" ]; then
    echo "ERROR You should set JAVA_HOME"
    echo "Exiting!"
    exit 1
fi


C_INCLUDE_PATH="${JAVA_HOME}/include:${JAVA_HOME}/include/linux:/System/Library/Frameworks/JavaVM.framework/Headers"
export C_INCLUDE_PATH

#   rm -f *.java
#   rm -f sodium_wrap.c
#   rm -f *.so

#   swig -java sodium.i
#   swig -java -package org.abstractj.kalium -outdir ../src/main/java/org/abstractj/kalium sodium.i


jnilib=libkaliumjni.so
destlib=/usr/lib
if uname -a | grep -q -i darwin; then
  jnilib=libkaliumjni.jnilib
  destlib=/usr/lib/java
  if [ ! -d $destlib ]; then
      sudo mkdir $destlib
  fi
else
    sudo ldconfig
fi
#echo $jnilib
#echo $destlib
#echo $destlib/$jnilib 

#sudo cp /usr/local/lib/libsodium.* /usr/lib

gcc -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux sodium_wrap.c sodium_jni_buffer.c -Wno-variadic-macros -shared -fPIC -L/usr/lib -lsodium -o $jnilib
sudo rm -f $destlib/$jnilib  
sudo cp $jnilib $destlib
