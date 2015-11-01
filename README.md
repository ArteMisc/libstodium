# libstodium

libstodium was born a fork of
[Robosodium](https://github.com/GerardSoleCa/Robosodium), which was born as a
fork of [kalium-jni](https://github.com/joshjdevl/kalium-jni/). With this
library you will be able to compile libsodium for Android platforms and
automatically create the wrapper for the JNI. It can also be added to Android
Studio as a module, using the generated
build.gradle/libstodium.iml/proguard-rules.pro files.

Credits to:
* [**Libsodium**](https://github.com/jedisct1/libsodium): author [Frank Denis](https://github.com/jedisct1) and [Contributors](https://github.com/jedisct1/libsodium/graphs/contributors)
* [**Kalium-jni**](https://github.com/joshjdevl/kalium-jni/): author [joshjdevl](https://github.com/joshjdevl) and [Contributors](https://github.com/joshjdevl/kalium-jni/graphs/contributors)
* [**Robosodium**](https://github.com/GerardSoleCa/Robosodium): author [GerardSoleCa](https://github.com/GerardSoleCa)

### How to

*When you plan to use libstodium in an Android Studio project, I would recommend
cloning the repository into a subdirectory of the project root.*

1. First of all download this repository and its submodules:
  ```bash
  $ git clone https://github.com/ArteMisc/libstodium.git
  $ git submodule init 
  $ git submodule update
  ```

2. Start from first clone:
  ```bash
  $ ./do_the_job.sh
  ```
  
3. Build JNI for Linux instead of Android:
  ```bash
  $ ./do_the_job.sh linux
  ```
4. Where to find the compiled libs:
  ```bash
  cd libs # Libs for Android using the architecture dirs
  cd linux_lib # Lib for Linux. To be used copy to /usr/lib for example. Or just place anywhere you want
  ```

5. If something goes wrong or you want to re-run parts of the compilation, just call the following scripts:
  ```bash
  do_the_job.sh              # Start and run all the scripts
  install_software.sh        # First update aptitude cache and install necessary packages
  build_jni_linux.sh         # Build libsodium with jni for linux.
  download_ndk.sh            # Download the required Android NDK
  build_android_libsodium.sh # Compile Libsodium for Android
  build_jni.sh               # Generate the JNI library (*.so)
  ```

### License

Each part has its own software license, including:
* **Libsodium** [ISC License](https://github.com/jedisct1/libsodium/blob/master/LICENSE)
* **kalium-jni** [Apache License. Version 2.0](https://github.com/joshjdevl/kalium-jni/blob/master/LICENSE.txt)
* **Robosodium** [Apache License. Version 2.0](https://github.com/GerardSoleCa/Robosodium/blob/master/LICENSE.txt)
* **libstodium** [Apache License. Version 2.0](https://github.com/ArteMisc/libstodium/blob/master/LICENSE.txt)
