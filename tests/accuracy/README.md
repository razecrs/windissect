# DUI70 accuracy comparison

Run from the repository root after cloning the local comparison corpus:

```powershell
cargo run -- refine `
  --ir ..\test\accuracy\refined-current\dui70.refined.json `
  --reference ..\prior-art\explorerpatcher-dui70 `
  --out tests\accuracy\ep-refine.json
```

The raw comparison is recorded in [RAW_1V1.md](RAW_1V1.md). The reference
corpus is treated as a comparison oracle; it is not promoted to proof.
