# Argon2 port

Ported `include/argon2.h` from: https://github.com/P-H-C/phc-winner-argon2 \
This project is conforming to [commit f57e61e](https://github.com/P-H-C/phc-winner-argon2/tree/f57e61e19229e23c4445b85494dbf7c07de721cb) of the aforementioned repo on github.

Some recommendations for settings can be found here:

- https://tobtu.com/minimum-password-settings/
- https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

The `argon2.d` file contains the relevant information and self contained except for `import core.stdc.limits : CHAR_BIT`.
That dependency can be dropped by setting `enum CHAR_BIT = 8;` (depending on platform).

### MSVC argon2 build

Project includes a script to build the argon2 static libary with the MSVC toolchain (`cl`, `lib`) since `msbuild Argon2.sln` (from the official argon2 repo) is specified to use Windows SDK version 8.1 only.

Invoke with: `dmd -run other\build_argon2_msvc.d --help`

## Todo:

- [x] port api
- [x] build script to build git repo argon2 with MSVC toolchain
- [ ] Add to dub registry
