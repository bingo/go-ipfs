# AAA IPFS Extension
This package extends ipfs with AAA Chain commands.

1. ipfs check <path>

This command extension would help user to quickly verify/check the given file already exists on the AAA chain or not.

```
USAGE
  ipfs check <path>... - To check file's existence before adding.

SYNOPSIS
  ipfs check [--quiet | -q] [--quieter | -Q] [--progress | -p] [--chunker=<chunker> | -s] [--cid-version=<cid-version>] [--hash=<hash>] [--raw-leaves] [--] <path>...

ARGUMENTS

  <path>... - The path to a file to be verified/checked of existence.

OPTIONS

  -q,          --quiet    bool   - Write minimal output.
  -Q,          --quieter  bool   - Write only final result.
  -p,          --progress bool   - Display progress data.
  -s,          --chunker  string - Chunking algorithm, size-[bytes] or rabin-[min]-[avg]-[max]. Default: size-262144.
  --cid-version           int    - CID version. Defaults to 0 unless an option that depends on CIDv1 ispassed. (experimental).
  --hash                  string - Hash function to use. Implies CIDv1 if not sha2-256. (experimental).Default: sha2-256.
  --raw-leaves            bool   - Use raw blocks for leaf nodes. (experimental).

DESCRIPTION

  Check whether file exists through calculating MerkleDAG <hash> of file,
  then query ipfs network to see reference to <hash> exist or not.

  For example:

    > ipfs check exists.jpg
    Hash: QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH exists.jpg
    File already exists!
    > ipfs check nonexists.jpg
    Hash: QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH nonexists.jpg
    File does not exists!

  The chunker option, '-s', specifies the chunking strategy that dictates
  how to break files into blocks. Blocks with same content can
  be deduplicated. The default is a fixed block size of
  256 * 1024 bytes, 'size-262144'. Alternatively, you can use the
  rabin chunker for content defined chunking by specifying
  rabin-[min]-[avg]-[max] (where min/avg/max refer to the resulting
  chunk sizes). Using other chunking strategies will produce
  different hashes for the same file.

    > ipfs check --chunker=size-2048 ipfs-logo.svg
    Hash: QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH exists.jpg
    File already exists!
    > ipfs add --chunker=rabin-512-1024-2048 ipfs-logo.svg
    Hash: QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH nonexists.jpg
    File does not exists!

  Like 'ipfs add', you can also specify cid version, hash function and
  whether raw blocks for leaf nodes by:
    > ipfs check --cid-version=1 --hash=sha2-256 --raw-leaves ipfs-logo.svg
    Hash: QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH nonexists.jpg
    File does not exists!
```