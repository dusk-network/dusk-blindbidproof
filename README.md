

# zkproof
`import "gitlab.dusk.network/dusk-core/zkproof"`

* [Overview](#pkg-overview)
* [Index](#pkg-index)

## <a name="pkg-overview">Overview</a>
Package zkproof contains the Go APIs to generate and verify
a zero-knownledge prove for the Dusk's Blind Bid.

Under the hood is using named pipes for a fast IPC with the Blind Bid
process.

A concrete implementation of the Blind Bid can be found here:
<a href="https://gitlab.dusk.network/dusk-core/blindbidproof">https://gitlab.dusk.network/dusk-core/blindbidproof</a>




## <a name="pkg-index">Index</a>
* [func CalculateM(k ristretto.Scalar) ristretto.Scalar](#CalculateM)
* [func CalculateX(d, m ristretto.Scalar) ristretto.Scalar](#CalculateX)
* [type BinReader](#BinReader)
  * [func NewBinReader(r io.Reader) BinReader](#NewBinReader)
  * [func (r *BinReader) Read(data interface{})](#BinReader.Read)
  * [func (r *BinReader) ReadVarBytes() []byte](#BinReader.ReadVarBytes)
  * [func (r *BinReader) ReadVarString() string](#BinReader.ReadVarString)
  * [func (r *BinReader) VarRead(data interface{})](#BinReader.VarRead)
* [type BinWriter](#BinWriter)
  * [func NewBinWriter(w io.Writer) BinWriter](#NewBinWriter)
  * [func (w *BinWriter) VarWrite(data interface{})](#BinWriter.VarWrite)
  * [func (w *BinWriter) Write(data interface{})](#BinWriter.Write)
  * [func (w *BinWriter) WriteVarBytes(b []byte)](#BinWriter.WriteVarBytes)
  * [func (w *BinWriter) WriteVarString(s string)](#BinWriter.WriteVarString)
* [type NamedPipe](#NamedPipe)
  * [func NewNamedPipe(path string) NamedPipe](#NewNamedPipe)
  * [func (np *NamedPipe) Read(p []byte) (n int, err error)](#NamedPipe.Read)
  * [func (np *NamedPipe) ReadAll() ([]byte, error)](#NamedPipe.ReadAll)
  * [func (np *NamedPipe) Write(p []byte) (n int, err error)](#NamedPipe.Write)
* [type ZkProof](#ZkProof)
  * [func Prove(d, k, seed ristretto.Scalar, bidList []ristretto.Scalar) ZkProof](#Prove)
  * [func (proof *ZkProof) Verify(seed ristretto.Scalar) bool](#ZkProof.Verify)


#### <a name="pkg-files">Package files</a>
[bidproof.go](/src/target/bidproof.go) [binReader.go](/src/target/binReader.go) [binWriter.go](/src/target/binWriter.go) [pipe.go](/src/target/pipe.go) 





## <a name="CalculateM">func</a> [CalculateM](/src/target/bidproof.go?s=2841:2893#L122)
``` go
func CalculateM(k ristretto.Scalar) ristretto.Scalar
```
CalculateM calculates `H(k)`.



## <a name="CalculateX">func</a> [CalculateX](/src/target/bidproof.go?s=2716:2771#L116)
``` go
func CalculateX(d, m ristretto.Scalar) ristretto.Scalar
```
CalculateX calculates the blind bid `X`.




## <a name="BinReader">type</a> [BinReader](/src/target/binReader.go?s=106:157#L10)
``` go
type BinReader struct {
    // contains filtered or unexported fields
}

```
BinReader holds data for a binary reader.







### <a name="NewBinReader">func</a> [NewBinReader](/src/target/binReader.go?s=220:260#L16)
``` go
func NewBinReader(r io.Reader) BinReader
```
NewBinReader returns a BinReader for the reader provided.





### <a name="BinReader.Read">func</a> (\*BinReader) [Read](/src/target/binReader.go?s=485:527#L24)
``` go
func (r *BinReader) Read(data interface{})
```
Read reads structured binary data from `r` into `data`, using little endian
order.
The argument must be a fixed-size value or a slice of fixed-size
values, or a pointer to such data.




### <a name="BinReader.ReadVarBytes">func</a> (\*BinReader) [ReadVarBytes](/src/target/binReader.go?s=1111:1152#L50)
``` go
func (r *BinReader) ReadVarBytes() []byte
```
ReadVarBytes reads a variable length byte array from `r`.




### <a name="BinReader.ReadVarString">func</a> (\*BinReader) [ReadVarString](/src/target/binReader.go?s=1306:1348#L60)
``` go
func (r *BinReader) ReadVarString() string
```
ReadVarString reads a variable length string array from `r`.




### <a name="BinReader.VarRead">func</a> (\*BinReader) [VarRead](/src/target/binReader.go?s=797:842#L34)
``` go
func (r *BinReader) VarRead(data interface{})
```
VarRead reads a variable length structured binary data from `r` into `data`,
using little endian order.
The argument must be a `uint*`, a `string`, or an array of `byte`.




## <a name="BinWriter">type</a> [BinWriter](/src/target/binWriter.go?s=99:150#L9)
``` go
type BinWriter struct {
    // contains filtered or unexported fields
}

```
BinWriter holds data for a binary writer.







### <a name="NewBinWriter">func</a> [NewBinWriter](/src/target/binWriter.go?s=213:253#L15)
``` go
func NewBinWriter(w io.Writer) BinWriter
```
NewBinWriter returns a BinWriter for the writer provided.





### <a name="BinWriter.VarWrite">func</a> (\*BinWriter) [VarWrite](/src/target/binWriter.go?s=812:858#L34)
``` go
func (w *BinWriter) VarWrite(data interface{})
```
VarWrite writes the binary representation of a variable length `data`
into `w`.
The argument must be a `uint*`, a `string`, or an array of `byte`;
it will fallback to `Write` otherwise.




### <a name="BinWriter.Write">func</a> (\*BinWriter) [Write](/src/target/binWriter.go?s=480:523#L23)
``` go
func (w *BinWriter) Write(data interface{})
```
Write writes the binary representation of `data` into `w` using little endian
order.
The argument must be a fixed-size value or a slice of fixed-size
values, or a pointer to such data.




### <a name="BinWriter.WriteVarBytes">func</a> (\*BinWriter) [WriteVarBytes](/src/target/binWriter.go?s=1270:1313#L57)
``` go
func (w *BinWriter) WriteVarBytes(b []byte)
```
WriteVarBytes writes a variable length byte array.




### <a name="BinWriter.WriteVarString">func</a> (\*BinWriter) [WriteVarString](/src/target/binWriter.go?s=1138:1182#L52)
``` go
func (w *BinWriter) WriteVarString(s string)
```
WriteVarString writes a variable length `string` into `w`.




## <a name="NamedPipe">type</a> [NamedPipe](/src/target/pipe.go?s=118:197#L12)
``` go
type NamedPipe struct {
    // contains filtered or unexported fields
}

```
NamedPipe holds data for a named pipe.







### <a name="NewNamedPipe">func</a> [NewNamedPipe](/src/target/pipe.go?s=254:294#L19)
``` go
func NewNamedPipe(path string) NamedPipe
```
NewNamedPipe returns a NamedPipe on the path given.





### <a name="NamedPipe.Read">func</a> (\*NamedPipe) [Read](/src/target/pipe.go?s=1496:1550#L53)
``` go
func (np *NamedPipe) Read(p []byte) (n int, err error)
```
Read reads up to `len(p)` bytes  from the named pipe into `p`.
It returns the number of bytes read `(0 <= n <= len(p))` and any error
encountered.

Read should be used only when a `io.Reader` interface is needed: since a
direct reading operation to the named pipe is blocking, the NamedPipe uses
an internal buffer wrapped around `ReadAll` to handles multiple reading
calls without accessing every call to the underlying named pipe.

Therefore, `ReadAll` should be used when `io.Reader` interface is not
necesssary.

This operation locks the `NamedPipe`.
the calling goroutine blocks until the function's end.




### <a name="NamedPipe.ReadAll">func</a> (\*NamedPipe) [ReadAll](/src/target/pipe.go?s=2166:2212#L78)
``` go
func (np *NamedPipe) ReadAll() ([]byte, error)
```
ReadAll reads from the named pipe until an error or EOF and returns the data
it read.
A successful call returns `err == nil`, not `err == EOF`.
Because ReadAll is defined to read from src until EOF, it does not treat an
EOF from Read as an error to be reported.

This operation locks the `NamedPipe`.
the calling goroutine blocks until the function's end.




### <a name="NamedPipe.Write">func</a> (\*NamedPipe) [Write](/src/target/pipe.go?s=692:747#L32)
``` go
func (np *NamedPipe) Write(p []byte) (n int, err error)
```
Write writes `len(p)` bytes from `p` to the named pipe.
It returns the number of bytes written from `p (0 <= n <= len(p))` and any
error encountered that caused the write to stop early.

This operation locks the `NamedPipe`.
the calling goroutine blocks until the function's end.




## <a name="ZkProof">type</a> [ZkProof](/src/target/bidproof.go?s=524:635#L22)
``` go
type ZkProof struct {
    Proof         []byte
    Score         []byte
    Z             []byte
    BinaryBidList []byte
}

```
ZkProof holds all of the returned values from a generated proof.







### <a name="Prove">func</a> [Prove](/src/target/bidproof.go?s=1131:1206#L44)
``` go
func Prove(d, k, seed ristretto.Scalar, bidList []ristretto.Scalar) ZkProof
```
Prove creates a zkproof using `d`, `k`, `seed` and `pubList`, and returns
a ZkProof data type.





### <a name="ZkProof.Verify">func</a> (\*ZkProof) [Verify](/src/target/bidproof.go?s=2196:2252#L91)
``` go
func (proof *ZkProof) Verify(seed ristretto.Scalar) bool
```
Verify a ZkProof using the provided seed.
Returns `true` or `false` depending on whether it is successful.








- - -

