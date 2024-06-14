Place the static library in the `./libs` directory to have `dub run` work without modifications to `dub.json`

**Note: not following naming conventions might break linking**

- Windows: `argon2.lib` \
  (generally: `<lib-name>.lib`)
- Posix: `libargon2.a` \
  (generally: `lib<lib-name>.a`)

Ex: deviating from posix convention requires using absolute path to library instead of relative path.
