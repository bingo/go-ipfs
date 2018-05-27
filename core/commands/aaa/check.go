package aaacmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	blockservice "github.com/ipfs/go-ipfs/blockservice"
	oldcmds "github.com/ipfs/go-ipfs/commands"
	core "github.com/ipfs/go-ipfs/core"
	"github.com/ipfs/go-ipfs/core/coreunix"
	dag "github.com/ipfs/go-ipfs/merkledag"
	dagtest "github.com/ipfs/go-ipfs/merkledag/test"
	mfs "github.com/ipfs/go-ipfs/mfs"
	ft "github.com/ipfs/go-ipfs/unixfs"

	logging "gx/ipfs/QmRb5jh8z2E8hMGN2tkvs1yHynUanqnZ3UeKwgN1i9P1F8/go-log"
	cmds "gx/ipfs/QmTjNRVt2fvaRFu93keEC7z5M1GS1iH6qZ9227htQioTUY/go-ipfs-cmds"
	mh "gx/ipfs/QmZyZDi491cCNTLfAhwcaDii2Kg4pwKRkhqQzURGDvY6ua/go-multihash"
	cmdkit "gx/ipfs/QmceUdzxkimdYsgtX733uNgzf1DLHyBKN6ehGSp85ayppM/go-ipfs-cmdkit"
	files "gx/ipfs/QmceUdzxkimdYsgtX733uNgzf1DLHyBKN6ehGSp85ayppM/go-ipfs-cmdkit/files"
	pb "gx/ipfs/QmeWjRodbcZFKe5tMN7poEx3izym6osrLSnTLf9UjJZBbs/pb"
)

var log = logging.Logger("core/commands/aaa")

const (
	quietOptionName      = "quiet"
	quieterOptionName    = "quieter"
	progressOptionName   = "progress"
	chunkerOptionName    = "chunker"
	cidVersionOptionName = "cid-version"
	hashOptionName       = "hash"
	rawLeavesOptionName  = "raw-leaves"
)

const checkerOutChanSize = 8

//CheckCmd To check whether specified file exists
var CheckCmd = &cmds.Command{
	Helptext: cmdkit.HelpText{
		Tagline: "To check file's existence before adding.",
		ShortDescription: `
To check whether specified file does exist already in the network.
This is a quick combination of 'ipfs add --only-hash <file>' and
'ipfs object get <hash> commands, to see whether the file's content already
stored in the network.
`,
		LongDescription: `
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
`,
	},

	Arguments: []cmdkit.Argument{
		cmdkit.FileArg("path", true, true, "The path to a file to be verified/checked of existence.").EnableStdin(),
	},
	Options: []cmdkit.Option{
		cmdkit.BoolOption(quietOptionName, "q", "Write minimal output."),
		cmdkit.BoolOption(quieterOptionName, "Q", "Write only final result."),
		cmdkit.BoolOption(progressOptionName, "p", "Display progress data."),
		cmdkit.StringOption(chunkerOptionName, "s", "Chunking algorithm, size-[bytes] or rabin-[min]-[avg]-[max]").WithDefault("size-262144"),
		cmdkit.IntOption(cidVersionOptionName, "CID version. Defaults to 0 unless an option that depends on CIDv1 is passed. (experimental)"),
		cmdkit.StringOption(hashOptionName, "Hash function to use. Implies CIDv1 if not sha2-256. (experimental)").WithDefault("sha2-256"),
		cmdkit.BoolOption(rawLeavesOptionName, "Use raw blocks for leaf nodes. (experimental)"),
	},
	PreRun: func(req *cmds.Request, env cmds.Environment) error {
		return nil
	},
	Run: func(req *cmds.Request, res cmds.ResponseEmitter, env cmds.Environment) {
		n, err := GetNode(env)
		if err != nil {
			res.SetError(err, cmdkit.ErrNormal)
			return
		}

		_, err = n.Repo.Config()
		if err != nil {
			res.SetError(err, cmdkit.ErrNormal)
			return
		}

		chunker, _ := req.Options[chunkerOptionName].(string)
		cidVer, cidVerSet := req.Options[cidVersionOptionName].(int)
		hashFunStr, _ := req.Options[hashOptionName].(string)
		rawblks, rbset := req.Options[rawLeavesOptionName].(bool)

		// The arguments are subject to the following constraints.
		// (hash != "sha2-256") -> CIDv1
		if hashFunStr != "sha2-256" && cidVer == 0 {
			if cidVerSet {
				res.SetError(
					errors.New("CIDv0 only supports sha2-256"),
					cmdkit.ErrClient,
				)
				return
			}
			cidVer = 1
		}

		// cidV1 -> raw blocks (by default)
		if cidVer > 0 && !rbset {
			rawblks = true
		}

		prefix, err := dag.PrefixForCidVersion(cidVer)
		if err != nil {
			res.SetError(err, cmdkit.ErrNormal)
			return
		}

		hashFunCode, ok := mh.Names[strings.ToLower(hashFunStr)]
		if !ok {
			res.SetError(fmt.Errorf("unrecognized hash function: %s", strings.ToLower(hashFunStr)), cmdkit.ErrNormal)
			return
		}

		prefix.MhType = hashFunCode
		prefix.MhLength = -1

		//hash generation only, no need to write to disk
		nilnode, err := core.NewNode(n.Context(), &core.BuildCfg{
			//TODO: need this to be true or all files
			// hashed will be stored in memory!
			NilRepo: true,
		})
		if err != nil {
			res.SetError(err, cmdkit.ErrNormal)
			return
		}
		n = nilnode

		addblockstore := n.Blockstore

		exch := n.Exchange

		bserv := blockservice.New(addblockstore, exch) // hash security 001
		dserv := dag.NewDAGService(bserv)

		outChan := make(chan interface{}, checkerOutChanSize)

		fileChecker, err := coreunix.NewAdder(req.Context, n.Pinning, n.Blockstore, dserv)
		if err != nil {
			res.SetError(err, cmdkit.ErrNormal)
			return
		}

		fileChecker.Out = outChan
		fileChecker.Chunker = chunker
		fileChecker.RawLeaves = rawblks

		//hash only
		md := dagtest.Mock()
		emptyDirNode := ft.EmptyDirNode()
		// Use the same prefix for the "empty" MFS root as for the file adder.
		emptyDirNode.Prefix = *fileChecker.Prefix
		mr, err := mfs.NewRoot(req.Context, md, emptyDirNode, nil)
		if err != nil {
			res.SetError(err, cmdkit.ErrNormal)
			return
		}

		fileChecker.SetMfsRoot(mr)

		checkFile := func(f files.File) error {
			// Iterate over each top-level file and add individually. Otherwise the
			// single files.File f is treated as a directory, affecting hidden file
			// semantics.
			for {
				file, err := f.NextFile()
				if err == io.EOF {
					// Finished the list of files.
					break
				} else if err != nil {
					return err
				}
				if err := fileChecker.AddFile(file); err != nil {
					return err
				}
			}

			// copy intermediary nodes from editor to our actual dagservice
			_, err := fileChecker.Finalize()
			if err != nil {
				return err
			}

			return nil
		}

		errCh := make(chan error)
		go func() {
			var err error
			defer func() { errCh <- err }()
			defer close(outChan)
			err = checkFile(req.Files)
		}()

		defer res.Close()

		err = res.Emit(outChan)
		if err != nil {
			log.Error(err)
			return
		}
		err = <-errCh
		if err != nil {
			res.SetError(err, cmdkit.ErrNormal)
		}
	},
	PostRun: cmds.PostRunMap{
		cmds.CLI: func(req *cmds.Request, re cmds.ResponseEmitter) cmds.ResponseEmitter {
			reNext, res := cmds.NewChanResponsePair(req)
			outChan := make(chan interface{})

			sizeChan := make(chan int64, 1)

			sizeFile, ok := req.Files.(files.SizeFile)
			if ok {
				// Could be slow.
				go func() {
					size, err := sizeFile.Size()
					if err != nil {
						log.Warningf("error getting files size: %s", err)
						// see comment above
						return
					}

					sizeChan <- size
				}()
			} else {
				// we don't need to error, the progress bar just
				// won't know how big the files are
				log.Warning("cannot determine size of input file")
			}

			progressBar := func(wait chan struct{}) {
				defer close(wait)

				quiet, _ := req.Options[quietOptionName].(bool)
				quieter, _ := req.Options[quieterOptionName].(bool)
				quiet = quiet || quieter

				progress, _ := req.Options[progressOptionName].(bool)

				var bar *pb.ProgressBar
				if progress {
					bar = pb.New64(0).SetUnits(pb.U_BYTES)
					bar.ManualUpdate = true
					bar.ShowTimeLeft = false
					bar.ShowPercent = false
					bar.Output = os.Stderr
					bar.Start()
				}

				lastFile := ""
				lastHash := ""
				var totalProgress, prevFiles, lastBytes int64

			LOOP:
				for {
					select {
					case out, ok := <-outChan:
						if !ok {
							if quieter {
								fmt.Fprintln(os.Stdout, lastHash)
							}

							break LOOP
						}
						output := out.(*coreunix.AddedObject)
						if len(output.Hash) > 0 {
							lastHash = output.Hash
							if quieter {
								continue
							}

							if progress {
								// clear progress bar line before we print "added x" output
								fmt.Fprintf(os.Stderr, "\033[2K\r")
							}
							if quiet {
								fmt.Fprintf(os.Stdout, "%s\n", output.Hash)
							} else {
								fmt.Fprintf(os.Stdout, "added %s %s\n", output.Hash, output.Name)
							}

						} else {
							if !progress {
								continue
							}

							if len(lastFile) == 0 {
								lastFile = output.Name
							}
							if output.Name != lastFile || output.Bytes < lastBytes {
								prevFiles += lastBytes
								lastFile = output.Name
							}
							lastBytes = output.Bytes
							delta := prevFiles + lastBytes - totalProgress
							totalProgress = bar.Add64(delta)
						}

						if progress {
							bar.Update()
						}
					case size := <-sizeChan:
						if progress {
							bar.Total = size
							bar.ShowPercent = true
							bar.ShowBar = true
							bar.ShowTimeLeft = true
						}
					case <-req.Context.Done():
						// don't set or print error here, that happens in the goroutine below
						return
					}
				}
			}

			go func() {
				// defer order important! First close outChan, then wait for output to finish, then close re
				defer re.Close()

				if e := res.Error(); e != nil {
					defer close(outChan)
					re.SetError(e.Message, e.Code)
					return
				}

				wait := make(chan struct{})
				go progressBar(wait)

				defer func() { <-wait }()
				defer close(outChan)

				for {
					v, err := res.Next()
					if !cmds.HandleError(err, res, re) {
						break
					}

					select {
					case outChan <- v:
					case <-req.Context.Done():
						re.SetError(req.Context.Err(), cmdkit.ErrNormal)
						return
					}
				}
			}()

			return reNext
		},
	},
	Type: coreunix.AddedObject{},
}

// COPIED FROM ONE LEVEL UP - to bypass "cycle import" error

// GetNode extracts the node from the environment.
func GetNode(env interface{}) (*core.IpfsNode, error) {
	ctx, ok := env.(*oldcmds.Context)
	if !ok {
		return nil, fmt.Errorf("expected env to be of type %T, got %T", ctx, env)
	}

	return ctx.GetNode()
}
