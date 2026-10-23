# Contributing

## Running the tests

```
python3 -m pytest tests/
```

Pure Python logic, no YARA/ClamAV/Docker needed for most of the suite.

## Testing a Webmin UI change

`perl -c` on a file under `webmin/openxs/` by itself won't work - those
files `require` a shared library that only loads inside a real Webmin
install. Build and run the project's own Docker sandbox instead:

```
docker build -t openxs .
docker run -d --name openxs -p 10000:10000 openxs
```

Then test the actual page over HTTP against that container, not just a
syntax check - several real bugs this project has hit (an undefined
subroutine, a scrambled output order) only showed up that way.

## Pull requests

- Keep the diff focused - one change, one PR.
- Add or update a test for anything with real logic (a branch, a
  size/time limit, a parser). A one-line config change doesn't need one.
- See the PR template for what to check before marking it ready.

## Reporting a vulnerability

Don't open a PR or public issue for a security vulnerability - see
[SECURITY.md](SECURITY.md).
