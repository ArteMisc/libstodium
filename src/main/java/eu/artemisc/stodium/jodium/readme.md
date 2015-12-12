# Cryptographic Classes based on Godium

Godium is a package created to implement Golang's standard library's
cryptographic interfaces, such that the implementations were compatible with the
implementations found in libsodium.

Jodium is an attempt to use Stodium's Libsodium bindings to create
implementations of similar interfaces as the original ones found in Godium. It
does not directly follow the conventions of the Java Security Interfaces,
however it does try to blend in with the Java Standars library, such as
supporting Input/Output stream interfaces.
