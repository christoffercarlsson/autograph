# The Autograph Protocol

Autograph is an open, modular cryptographic protocol that implements a
decentralized credential management system. It is efficient enough to run on
virtually any type of device, completely offline.

> [!WARNING]\
> The security of this protocol has been analyzed together with researchers
> from Chalmers University of Technology. It is currently in the process of
> being peer-reviewed and the source code has yet to be independently audited.
> The protocol specification has been successfully verified using Verifpal, an
> automated tool for symbolic verification of cryptograhic protocols. Make your
> own judgement on whether or not the current state of this project is a good
> fit for you.

Currently, there are three native implementations of the protocol written in
[C](./cplusplus), [Go](./go), and [Rust](./rust). The C implementation
has bindings to [C++](./cplusplus), [Kotlin](./android), [Swift](./apple),
and [TypeScript](./typescript).

## License

The source code in this repository is licensed under [The Unlicense](./LICENSE).

The Autograph protocol specification is released into the public domain.

## Acknowledgements

The Autograph protocol was designed by Christoffer Carlsson.

The initial Autograph concept was developed by Christoffer Carlsson and Max
Molin.

Thanks to Elnaz Abolahrar for discussions around ownership verification and
trusted third parties.

Thanks to Daniel Bark for contributing the Go implementation.

Special thanks to Konstantin Lindström, Ivan Oleynikov (Chalmers), and Elena
Pagnin (Chalmers) for analyzing the security of Autograph.
