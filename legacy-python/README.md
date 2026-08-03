# legacy-python

The original Python implementation of C3, imported from the `articfox-c3` repository
before it was retired. Kept for reference — the maintained implementation is the Rust
one in the repository root.

Nothing here is wired into the Rust build. It does not compile, run, or get tested as
part of this project.

## A note on the config files

`api_config.json`, `control_config.json`, `pb_config.json` and `bots.json` are tracked
here with empty credentials and placeholder data, exactly as they were in the source
repository.

The root `.gitignore` lists these filenames, but **once a file is tracked, .gitignore no
longer applies to it**. If you ever populate one of these with a real token, git will
happily commit it. Copy them somewhere outside the repository before filling them in.
