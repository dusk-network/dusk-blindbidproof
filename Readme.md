## How to build the library

    $ cargo build --release

## How to run 

Two process needs to run.

The provider first:

    $ cargo run --release

And then a consumer:

    $ cd go
    $ go test -timeout 300s gitlab.dusk.network/dusk-core/blindbidproof/go -run "^(TestProveVerify)\$" -count 1

Or, for benchmarks:

    $  cd go
    $  go test -benchmem -run=^\$ gitlab.dusk.network/dusk-core/blindbidproof/go -bench "^(BenchmarkProveVerify)\$" -v
