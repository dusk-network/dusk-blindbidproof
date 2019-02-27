## WIP

Works, but a lot of things re-added to make it work on my latop

## How to build the library

    $ cargo build --release

## How to run go example

    $ cd go
    $ go run main.go

It's possible also build the rust lib from `./go` folder, so it's not needed change current directory for every code change:

    $ cd go
    $ cargo build --release
    $ go run main.go
