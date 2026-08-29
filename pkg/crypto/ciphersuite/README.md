# Ciphersuite Package

This package defines the public contracts and negotiation metadata for DTLS
cipher suites. Built-in record-protection implementations are private to DTLS
and live in `internal/ciphersuite`.

## Benchmarking

Implementation benchmarks are excluded from regular test runs. Run all DTLS
1.2 record-protection benchmarks from the repository root with:

```bash
go test -tags=bench ./internal/ciphersuite -bench=BenchmarkRecordProtection12 -benchmem
```

Select an algorithm and operation through the benchmark path, for example:

```bash
go test -tags=bench ./internal/ciphersuite \
  -bench='BenchmarkRecordProtection12/GCM/Seal' -benchmem
```

Standard Go benchmark flags such as `-benchtime`, `-count`, `-cpuprofile`, and
`-memprofile` are supported.
