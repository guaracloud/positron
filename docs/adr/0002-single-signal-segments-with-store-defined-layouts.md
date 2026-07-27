# Keep segments single-signal and their layouts store-defined

Every segment belongs to exactly one signal store. The storage kernel manages a common envelope for identity, signal type, time range, size, checksums, and payload references, while the owning signal store defines the internal blocks, indexes, statistics, and encodings. A universal physical format would couple the kernel to structures that do not fit every signal, while mixed-signal segments would couple otherwise independent lifecycle and optimization decisions.
