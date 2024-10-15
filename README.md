# sneak

![docs.rs](https://img.shields.io/docsrs/sneak)
 
High-level abstractions of *at-and-related *nix syscalls to build race condition-free, thread-safe, symlink traversal attack-safe user APIs.   

### Motivation
While building filesystem-abstracting APIs, you can easily run into race conditions: classic system calls, as exposed by Rust's filesystem library, often [do not provide sufficient protections in multi-threaded or multi-process applications](https://tldp.org/HOWTO/Secure-Programs-HOWTO/avoid-race.html). In more complex applications, especially if they run as root, you risk exposing yourself to time-of-check time-of-use (TOCTOU) race conditions, which can culminate to privilege escalation vulnerabilities. Up until recently, [`std::fs::remove_dir_all`] was [sensitive to this attack vector](https://github.com/rust-lang/rust/security/advisories/GHSA-r9cc-f5pr-p3j2).  

Unfortunately, avoiding these race conditions is not an easy task. You need to directly interact with specialized system calls, handle different operating systems and `unsafe` code. This library aims to provide a safe, easy to use yet ultra flexible API which doesn't hide away any implementation details.

### Getting started

See the (documentation)[https://docs.rs/sneak/latest/sneak].  

### License

This software is dual-licensed under the (MIT license)[LICENSE-MIT] and the (Apache-2.0 license)[LICENSE-APACHE].

